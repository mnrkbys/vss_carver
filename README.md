# vss_carver
Carves and recreates VSS catalog and store from Windows disk image.

## Requirement
- Python 3.6+ or Python 2.7+
- High speed CPU and high speed I/O storage

## Usage
1. Carves and creates VSS catalog and store
```
vss_carver.py -o <volume_offset_in_bytes> -i <path_to_disk_image> -c <catalog_file> -s <store_file>
```
2. (Optional) Manipulates VSS catalog entries
```
vss_catalog_manipulator.py {list,move,remove,enable,disable} (see more details with "-h")
```
3. Mounts VSS Snapshot with the use of extended vshadowmount (You can get extended vshadowmount from [here](https://github.com/mnrkbys/vss_carver/tree/master/extended-libvshadow))
```
vshadowmount -o <volume_offset_in_bytes> -c <catalog_file> -s <store_file> <path_to_disk_image> <mount_point>
```

## Installation
    $ git clone https://github.com/mnrkbys/vss_carver

## Limitation
vss_carver.py only supports raw disk images. Therefore, E01, VMDK, VHDX and other disk images are needed to convert into a raw disk image or mount as a raw disk image with libewf, libvmdk and so on.

## Author
[Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License
[MIT](http://opensource.org/licenses/mit-license.php)
