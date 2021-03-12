#!/usr/bin/env python

import hashlib
import sys
import angr
import logging
from struct import pack_into, unpack_from
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Config DES key for Archer C3200
KEY = b'\x47\x8d\xa5\x0b\xf9\xe3\xd2\xcf'

# Set log level for loggers configured by angr and/or its dependencies
LOGLEVEL = 'ERROR'
ANGR_LOGGERS = [logging.getLogger('angr'), logging.getLogger('cle')]
any(map(lambda logger: logger.setLevel(LOGLEVEL), ANGR_LOGGERS))


def compress(data):
    # Based on the cen_uncompressBuff snippet from
    # https://pwn2learn.dusuel.fr/code/get_config_creds_tl-wr902ac.py
    # Blog post
    # https://pwn2learn.dusuel.fr/blog/unauthenticated-root-shell-on-tp-link-tl-wr902ac-router/
    comp_sz = len(data)
    comp_buf_sz = 0x12000

    # start the angr machinery
    proj = angr.Project('libcutil.so', load_options={'auto_load_libs': False})
    compress_symbol = proj.loader.find_symbol('cen_compressBuff')
    compress_start = compress_symbol.rebased_addr
    compress_end = compress_start + compress_symbol.size - \
        0xc  # 0x73fc TODO: figure out a better way to find ret
    opts = {
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        angr.options.STRICT_PAGE_ACCESS,
        angr.options.UNICORN,
    }
    state = proj.factory.blank_state(addr=compress_start, add_options=opts)

    # write the data on stack (word/32bit aligned address)
    state.regs.sp -= comp_sz + (4 - (comp_sz % 4))
    comp = state.regs.sp
    state.memory.store(comp, state.solver.BVV(data, comp_sz * 8))

    # "allocate" room for compressed data on stack (word/32bit aligned address)
    state.regs.sp -= comp_buf_sz + (4 - (comp_buf_sz % 4))
    comp_buf = state.regs.sp

    comp_buf_start = comp_buf + comp_buf_sz
    comp_buf_sz_out = comp_buf + comp_buf_sz - 0x8000

    # set up registers
    state.regs.r0 = comp  # first argument to cen_compressBuff()
    state.regs.r1 = comp_sz  # second argument to cen_compressBuff()
    state.regs.r2 = comp_buf_sz_out  # third argument to cen_compressBuff()
    state.regs.r3 = comp_buf  # as usual for MIPS
    state.regs.r15 = compress_start

    initial_sp = state.regs.sp
    # launch the simulation
    simgr = proj.factory.simulation_manager(state)
    paths = simgr.explore(find=compress_end)

    # get the end state, and the config (compressed data)
    state_end = paths.found[0]
    # expected size is returned in r0
    lsize = state_end.solver.eval(state_end.regs.r0)
    return state_end.solver.eval(state_end.memory.load(comp_buf,
                                                       lsize, angr.archinfo.Endness.LE), cast_to=bytes)


def uncompress(src):
    # Modified from https://github.com/sta-c0000/tpconf_bin_xml
    '''Uncompress buffer'''
    block16_countdown = 0  # 16 byte blocks
    block16_dict_bits = 0  # bits for dictionnary bytes

    def get_bit():
        nonlocal block16_countdown, block16_dict_bits, s_p
        if block16_countdown:
            block16_countdown -= 1
        else:
            block16_dict_bits = unpack_from('H', src, s_p)[0]
            s_p += 2
            block16_countdown = 0xF
        block16_dict_bits = block16_dict_bits << 1
        return (((block16_dict_bits >> 1) << 0x10) >> 0x1f) & 0x1
        # return 1 if block16_dict_bits & 0x10000 else 0 # went past bit

    def get_dict_ld():
        bits = 1
        while True:
            bits = (bits << 1) + get_bit()
            if not get_bit():
                break
        return bits

    size = unpack_from('<I', src, 0)[0]
    dst = bytearray(size)
    # Changed from original to start from index 8 instead of 4
    # Based on REing libcutil.so
    s_p = 8
    d_p = 0

    dst[d_p] = src[s_p]
    s_p += 1
    d_p += 1
    while d_p < size:
        if get_bit():
            num_chars = get_dict_ld() + 2
            msB = (get_dict_ld() - 2) << 8
            lsB = src[s_p]
            s_p += 1
            offset = d_p - (lsB + 1 + msB)
            for i in range(num_chars):
                # 1 by 1 ∵ sometimes copying previously copied byte
                dst[d_p] = dst[offset]
                d_p += 1
                offset += 1
        else:
            dst[d_p] = src[s_p]
            s_p += 1
            d_p += 1
    return dst


# Copied from https://github.com/sta-c0000/tpconf_bin_xml
def verify(src):
    # Try md5 hash excluding up to last 8 (padding) bytes
    if not any(src[:16] == hashlib.md5(src[16:len(src)-i]).digest() for i in range(8)):
        raise ValueError(
            'ERROR: Bad file or could not decrypt file - MD5 hash check failed!')


def read_bin(binpath):
    with open(binpath, 'rb') as fs:
        data = fs.read()
    cipher = DES.new(KEY, DES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    verify(decrypted)
    return uncompress(decrypted[16:])


def write_bin(data, binpath):
    cipher = DES.new(KEY, DES.MODE_ECB)
    comp = compress(data)
    final = hashlib.md5(comp).digest() + comp
    final += b'\x00' * (8 - (len(final) % 8))
    with open(binpath, 'wb') as fs:
        fs.write(cipher.encrypt(final))


def main():
    if not sys.argv[3:]:
        print(
            f'Usage: python {__file__} {{enc|dec}} <input bin/xml> <output bin/xml>', file=sys.stderr)
        sys.exit(1)
    try:
        mode = sys.argv[1].lower()
        if mode == 'dec':
            data = read_bin(sys.argv[2])
            with open(sys.argv[3], 'wb') as fs:
                fs.write(data)
        elif mode == 'enc':
            with open(sys.argv[2], 'rb') as fs:
                data = fs.read()
            write_bin(data, sys.argv[3])
        else:
            raise ValueError('Invalid mode')
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
