from PySquashfsImage import SquashFsImage
import sys


def find_squashfs_images(binpath):
    offsets = []
    with open(binpath, 'rb') as fs:
        data = fs.read()
        for i in range(len(data)-4):
            sig = data[i:i+4]
            if sig == b'hsqs':
                offsets.append(i)
    return offsets


def main():
    if not sys.argv[1:]:
        print(
            f'Usage: python {__file__} <path to firmware binary>', file=sys.stderr)
        sys.exit(1)
    binpath = sys.argv[1]
    offsets = find_squashfs_images(binpath)
    foundcutil = False
    for offset in offsets:
        try:
            image = SquashFsImage(binpath, offset=offset)
            for i in image.root.findAll():
                if not (i.isFolder() or i.isLink()):
                    if i.getName().endswith(b'libcutil.so'):
                        print(
                            f'Found libcutil at {i.getPath()}. Writing it to $PWD/libcutil.so')
                        with open('libcutil.so', 'wb') as fs:
                            fs.write(i.getContent())
                        foundcutil = True
                        break
        except Exception as e:
            pass
        if foundcutil:
            break
    if not foundcutil:
        print('Could not find libcutil.so. Are you sure this is the right firmware binary?', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
