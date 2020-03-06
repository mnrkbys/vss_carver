# vss_carver

Carves and recreates VSS catalog and store from Windows disk image.

## Requirement

- Python 3.7+ (I tested on Python 3.7.6)
- pyewf
- pyvmdk
- High speed CPU and high speed I/O storage

## Usage

1. Carves and creates VSS catalog and store

```bash
vss_carver.py -t <disk_image_type> -o <volume_offset_in_bytes> -i <disk_image> -c <catalog_file> -s <store_file>
```

2. (Optional) Manipulates VSS catalog entries

```bash
vss_catalog_manipulator.py {list,move,remove,enable,disable} (see more details with "-h")
```

3. Mounts VSS Snapshot with the use of extended vshadowmount (You can get extended vshadowmount from [here](https://github.com/mnrkbys/vss_carver/tree/master/extended-libvshadow))

```bash
vshadowmount -o <volume_offset_in_bytes> -c <catalog_file> -s <store_file> <path_to_disk_image> <mount_point>
```

## Installation of vss_carver

```bash
git clone https://github.com/mnrkbys/vss_carver
```

## Installation of dependencies

### Windows

[Yogesh](https://github.com/ydkhatri) is offering pre-compiled pyewf and pyvmdk in his [mac_apt](https://github.com/ydkhatri/mac_apt) repository. So, you don't have to compile them by yourself.
Follow [the instructions to install dependencies](https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3.7#Windows).

Of course, you can build them by yourself as same as Linux or macOS.

### Linux and macOS

Follow the instructions to build [libewf](https://github.com/libyal/libewf/wiki/Building) and [libvmdk](https://github.com/libyal/libvmdk/wiki/Building).

## Author

[Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License

[MIT](http://opensource.org/licenses/mit-license.php)
