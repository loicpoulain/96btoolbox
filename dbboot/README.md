# dbboot (Dragonboard-410c|820c)
Dragonboard boot image tool

### Usage

dbboot <abootimg> --extract|--update <blobtype> [--out outfile]

### Example

- Extract device-tree blob from boot partition (/dev/mmcblkp8)\
`$ dbboot /dev/mmcblkp8 -x dtb > dtb.img`\
or\
`$ dbboot /dev/mmcblkp8 -x dtb -o dtb.img`

- Update boot partition with new device-tree blob\
`$ cat dtb.img | dbboot /dev/mmcblkp8 -u dtb`\
or\
`$ dbboot /dev/mmcblkp8 -u dtb dtb.img`

- Update command line\
`$ dbboot /dev/mmcblkp8 -u cmdline "root=/dev/mmcblk0p10 console=ttyMSM0,115200n8"`

### Dragonboard boot image (abootimg) format

`+-----------------+`\
`| boot header.....| 1 page`\
`+-----------------+`\
`| kernel.gz + DTB.| n pages`\
`+-----------------+`\
`| ramdisk.........| m pages`\
`+-----------------+`\
`| second stage....| o pages`\
`+-----------------+`
