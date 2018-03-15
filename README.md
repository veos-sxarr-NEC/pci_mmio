# PCI Resource Access (MMIO) tool

## Compile and install

```
$ sudo yum install systemd-devel pciutils-devel
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

## Run

```
Usage: pci_mmio [<options>]

Selection of devices:
-s [[[[<domain>]:]<bus>]:][<slot>][.[<func>]]
-f <filename>   PCI device driver file

Selection of BARs:
-b <BAR number>

BAR Access Modes:
-r              Read Mode
-w              Write Mode
-D <filename>   Dump to file (IO Options will be ignored)

IO Options:
-o <offset>     Offset from top of each BAR
-d <data>       Data to write
-l <length>     IO Length
```

## Example

Read 8 byte of BAR2 offset 0x1400 from PCI device 08:00.0
```
$ sudo pci_mmio -s 0000:08:00.0 -b 2 -r -o 0x1400 -l 0x8
```

Dump BAR2 from PCI device 03:00.0 and compress with xz. Then check it with hexdump.
```
$ sudo pci_mmio -s 03:00.0 -D /dev/stdout -b 2 | xz -z > 03:00.0-bar2.xz
$ xz --decompress --stdout 03:00.0-bar2.xz | hexdump -e '"%08_ax: " 1/8 "%016x" "\n"' | less
```
