# archerc3200-tools
A collection of tools to aid in modifying TP-Link Archer C3200 configuration backups.
Based on [tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml) and inspired by [pwn2learn's writeup on rooting The TL-WR902AC](https://pwn2learn.dusuel.fr/blog/unauthenticated-root-shell-on-tp-link-tl-wr902ac-router/).

## Prerequisites
This project makes use of `pipenv`, so make sure you have it installed.

Install the dependencies and prepare a new virtual env with `pipenv install`. Activate the environment with `pipenv shell`.

### Getting the required `libcutil.so`
A shared library from the Archer C3200's firmware is needed by `bintool.py` for the XML to bin file compression functionality. Unfortunately, that shared library cannot be distributed as part of this repository, so you'll have to get a copy of it yourself. You could, for example, run the following commands to do so:

```sh
wget "https://static.tp-link.com/res/down/soft/Archer_C3200(EU)_V1_160712.zip" -O firmware.zip
unzip -o -d tmp-firmware firmware.zip 
find tmp-firmware -type f -name '*.bin' -exec python exlibcutil.py {} \;
```

Delete the temporary files when done:
```sh
find tmp-firmware -delete
rm firmware.zip
```

If it all went well, you should have `libcutil.so` at the root directory in this repository. You can verify that the file matches the library that these tools were tested against (as of 2021-03-10) with `sha256sum -c libcutil.hash`. It should show `libcutil.so: OK`, and ignore the warnings about improperly formatted files.
It doesn't have to be the case that you end up with the same `libcutil.so` file as long as `bintool.py` works.

## Getting started
Go to your Archer C3200 web UI and get a backup of your current settings`Advanced > System Tools > Backup & Restore > Backup`.
Use `bintool.py` to convert the .bin to an XML file
```sh
pipenv run python bintool.py dec conf.bin conf.xml
```

You can now modify the XML file as you wish. In order to execute files on startup, you can add an extra entry under the `<DeviceInfo>` section in the XML file as such:
```
<Description val="Test Router`command here`" />
```

**N.B. If the command has any XML special characters, they must be escaped.**

For example, in order to run a script (say, `init.sh`) off an NTFS or FAT32 formatted usb drive on startup, change the entry to (note the escaping of XML special characters):
```
<Description val="Test Router`(sleep 15;/var/usbdisk/sda1/init.sh)&gt;/dev/null &amp;`" />
```

A lot of the exploration options explained at [tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml#exploring-inside-the-router-advanced-users) also apply for the Archer C3200, so check them out if you'd like to delve deeper into the device.

Once you're done with your changes to the XML file, create the .bin file
```sh
pipenv run python bintool.py enc conf.xml conf.new.bin
```

And use the web interface to restore from the newly generated `conf.new.bin` file.

## Compiled binaries
For convenience, there are a couple of binaries provided [here](https://github.com/khalednassar/archerc3200-tools/tree/main/compiled-binaries) for the Archer C3200. These are the [nukedns](https://github.com/tjclement/nukedns) binary as well as a [busybox](https://busybox.net/) binary.
