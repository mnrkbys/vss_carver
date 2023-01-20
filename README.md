# vss_carver

Carves and recreates VSS catalog and store from Windows disk image.

## Requirement

- Python 3.7+ (I tested on Python 3.7.6)
- libvshadow (It has to be patched to support vss_carver)
- pyewf
- pyvmdk
- High speed CPU and high speed I/O storage

## Usage

1. Carves and recreates VSS catalog and store

```bash
vss_carver.py -t <disk_image_type> -o <volume_offset_in_bytes> -i <disk_image> -c <catalog_file> -s <store_file>
```

2. Sort the catalog entries based on the $SI modification timestamp of the specified file. To sort the catalog entries correctly, it must be updated frequently (default: /Windows/System32/winevt/Logs/System.evtx).

```bash
vss_catalog_sorter.py -t <disk_image_type> -o <volume_offset_in_bytes> -i <disk_image> -c <catalog_file> -s <store_file> -m <exported_$MFT>
```

3. (Optional) Manipulates VSS catalog entries

```bash
vss_catalog_manipulator.py {list,move,remove,enable,disable} (see more details with "-h")
```

4. Mounts VSS snapshots with the use of extended vshadowmount (You can get pre-compiled vshadowmount from [here](https://github.com/mnrkbys/precompiled_libyal_libs))

```bash
vshadowmount -o <volume_offset_in_bytes> -c <catalog_file> -s <store_file> <disk_image> <mount_point>
```

## Installation of vss_carver

```bash
git clone https://github.com/mnrkbys/vss_carver.git
```

## Installation of dependencies

### Windows

I am offering pre-compiled libyal libraries on [precompiled_libyal_libs repository](https://github.com/mnrkbys/precompiled_libyal_libs). I recommend using them.

[Yogesh](https://github.com/ydkhatri) also is offering pre-compiled pyewf and pyvmdk in his [mac_apt](https://github.com/ydkhatri/mac_apt) repository.
Follow [the instructions to install dependencies](https://github.com/ydkhatri/mac_apt/wiki/Installation-for-Python3.7#Windows).

Of course, you can build them by yourself as same as Linux or macOS.

### Linux and macOS

You have to compile libvshadow, libewf, and libvmdk. I'm offering patched source code on my repositories, [libvshadow](https://github.com/mnrkbys/libvshadow-vss_carver) and [libvmdk](https://github.com/mnrkbys/libvmdk-Shift_JIS).

Do git clone them above, then follow the instructions to build [libvshadow](https://github.com/libyal/libvshadow/wiki/Building), [libewf](https://github.com/libyal/libewf/wiki/Building) and [libvmdk](https://github.com/libyal/libvmdk/wiki/Building).

## Author

[Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License

[MIT](http://opensource.org/licenses/mit-license.php)
