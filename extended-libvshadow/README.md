# extended-libvshadow
The vshadowmount and libvshadow in here have been extended to read VSS catalog and store files (I wrote a patch based on libvshadow-20170902). This feature is expected to use together VSS catalog and store files that carved by vss_carver.py.

You can get its original source code here. [libvshadow](https://github.com/libyal/libvshadow)

Now, only binary files are distributed, because I need refactoring of patch I made. I will release the patch in the near future. These binaries were compiled with Visual Studio 2015.

## Requirement
- Dokany 0.7.4

## Usage
I added two new options, "-c" and "-s".
```
>vshadowmount.exe -h
vshadowmount 20170902

Use vshadowmount to mount a Windows NT Volume Shadow Snapshot (VSS)
volume

Usage: vshadowmount [ -o offset ] [ -X extended_options ]
                    [ -hvV ] source mount_point

        source:      the source file or device
        mount_point: the directory to serve as mount point

        -h:          shows this help
        -o:          specify the volume offset in bytes
        -v:          verbose output to stderr
                     vshadowmount will remain running in the foreground
        -V:          print version
        -X:          extended options to pass to sub system
        -c:          specify the VSS catalog file
        -s:          specify the VSS store file
```

## Installation
    $ git clone https://github.com/mnrkbys/vss_carver


## Author
Original Author: [Joachim Metz](https://github.com/joachimmetz)

Patch Author: [Minoru Kobayashi](https://twitter.com/unkn0wnbit)

## License
[LGPLv3+](http://www.gnu.org/licenses/)
