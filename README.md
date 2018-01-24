# vss_carver
Carves and recreates VSS catalog and store from Windows disk image.

## Requirement
- Python 3.6+ or Python 2.7+

## Usage
1. Carves and creates VSS catalog and store
```
vss_carver.py -o <volume_offset> -i <path_to_disk_image> -c <catalog_file> -s <store_file>
```
2. Manipulates VSS catalog entries
```
vss_catalog_manipulator.py {list,move,remove,enable,disable} (see more details with "-h")
```

## Installation
    $ git clone https://github.com/mnrkbys/vss_carver


## Author
[Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License
[MIT](http://opensource.org/licenses/mit-license.php)
