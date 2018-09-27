# extended-libvshadow
The vshadowmount and libvshadow in here have been extended to read restored VSS catalog and store files (I wrote a patch based on the source code of libvshadow with "git clone" on Sep. 13, 2018). This feature is expected to use together VSS catalog and store files that carved by vss_carver.py.

You can get its original source code here. [libvshadow](https://github.com/libyal/libvshadow)
And, the source code of extended-libvshadow is here. [extended-libvshadow](https://github.com/mnrkbys/libvshadow/tree/readable_restored_catalog_store)

I have already submitted a pull request for libvshadow, but it needs time to marge.

Binary files that I built are distributed in this repository. Windows binaries were compiled with Visual Studio 2017 and Debian packages were built on [SANS SIFT 3.0](https://digital-forensics.sans.org/community/downloads) (but I didn't tested deb packages, sorry).

If you need to run extended-libvshadow on other platforms, you have to compile its source code on them. In that case, you should refer to [libvshadow wiki](https://github.com/libyal/libvshadow/wiki/Building).

## Requirement
- Dokany 0.7.4 (on Windows)

## Usage
I added two new options, "-c" and "-s".
```
>vshadowmount.exe -h
vshadowmount 20180403

Use vshadowmount to mount a Windows NT Volume Shadow Snapshot (VSS) volume

Usage: vshadowmount [ -o offset ] [ -X extended_options ]
                    [ -hvV ] [ -c catalog ] [ -s store ] source mount_point

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
