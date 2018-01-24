#!/usr/bin/env python
# coding=utf-8

#
# vss_catalog_manipulator.py
# Manipulates VSS catalog file that recreated by vss_carver.py.
#
# Copyright (C) 2018 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT
#

import argparse
import struct
import copy
import datetime
from ctypes import *

vss_identifier = b'\x6B\x87\x08\x38\x76\xC1\x48\x4E\xB7\xAE\x04\x04\x6E\x6C\xC7\x52'


class CatalogBlockHeader(LittleEndianStructure):
    _fields_ = (
        ('vssid', c_char * 16),
        ('version', c_uint32),
        ('record_type', c_uint32),
        ('relative_catalog_offset', c_uint64),
        ('current_catalog_offset', c_uint64),
        ('next_catalog_offset', c_uint64),
        ('unknown_empty', c_char * 80)
    )

    def __init__(self, relative=0, current=0, next_offset=0):
        self.vssid = vss_identifier
        self.version = 0x1
        self.record_type = 0x2
        self.relative_catalog_offset = relative
        self.current_catalog_offset = current
        self.next_catalog_offset = next_offset
        self.unknown_empty = b'\x00'


class CatalogEntry0x00(LittleEndianStructure):
    _fields_ = (
        ('catalog_entry_type', c_uint64),
        ('unknown', c_char * 120)
    )

    def __init__(self):
        self.catalog_entry_type = 0x0
        self.unknown = b'\x00'


class CatalogEntry0x01(LittleEndianStructure):
    _fields_ = (
        ('catalog_entry_type', c_uint64),
        ('unknown', c_char * 120)
    )

    def __init__(self):
        self.catalog_entry_type = 0x01
        self.unknown = b'\x00'


class CatalogEntry0x02(LittleEndianStructure):
    _fields_ = (
        ('catalog_entry_type', c_uint64),
        ('volume_size', c_uint64),
        ('store_guid', c_char * 16),
        ('sequence_number', c_uint64),
        ('unknown_flags', c_uint64),
        ('shadow_copy_creation_time', c_uint64),
        ('unknown_empty', c_char * 72)
    )

    def __init__(self):
        self.catalog_entry_type = 0x02
        self.unknown_flags = 0x40
        self.unknown_empty = b'\x00'


class CatalogEntry0x03(LittleEndianStructure):
    _fields_ = (
        ('catalog_entry_type', c_uint64),
        ('store_block_list_offset', c_uint64),
        ('store_guid', c_char * 16),
        ('store_header_offset', c_uint64),
        ('store_block_range_offset', c_uint64),
        ('store_current_bitmap_offset', c_uint64),
        ('ntfs_file_reference', c_uint64),
        ('allocated_size', c_uint64),
        ('store_previous_bitmap_offset', c_uint64),
        ('unknown', c_uint64),
        ('unknown_empty', c_char * 40)
    )

    def __init__(self):
        self.catalog_entry_type = 0x03
        self.ntfs_file_reference = 0x0
        self.allocated_size = 0x0
        self.store_previous_bitmap_offset = 0x0
        self.unknown = 0x0
        self.unknown_empty = b'\x00'


class CatalogEntry(LittleEndianStructure):
    def __init__(self):
        self.enable = True
        self.catalog0x02 = CatalogEntry0x02()
        self.catalog0x03 = CatalogEntry0x03()


def read_catalog(f_catalog):
    list_catalog_entry = []
    catalog_block_header = CatalogBlockHeader()
    catalog_entry = CatalogEntry()
    catalog_file_offset = 0

    for catalog_block_offset in [0x0, 0x4000, 0x8000, 0xc000]:
        f_catalog.seek(catalog_block_offset)
        f_catalog.readinto(catalog_block_header)
        catalog_file_offset = catalog_file_offset + 128
        if not (catalog_block_header.vssid == vss_identifier and catalog_block_header.version == 0x1 and catalog_block_header.record_type == 0x2):
            exit("This file is not VSS catalog.")

        while catalog_file_offset < catalog_block_offset + 0x4000 - 128:
            catalog_entry_type, data = struct.unpack("<QQ", f_catalog.read(16))
            f_catalog.seek(-16, 1)

            if catalog_entry_type == 0x2:
                catalog_entry.enable = True
                f_catalog.readinto(catalog_entry.catalog0x02)
                f_catalog.readinto(catalog_entry.catalog0x03)
                catalog_file_offset = catalog_file_offset + 128 * 2
                if catalog_entry.catalog0x02.store_guid == catalog_entry.catalog0x03.store_guid:
                    list_catalog_entry.append(copy.deepcopy(catalog_entry))
                else:
                    exit("Corrupt catalog format.")
            elif catalog_entry_type == 0x1 and data != 0x0:
                catalog_entry.enable = False
                f_catalog.readinto(catalog_entry.catalog0x02)
                f_catalog.readinto(catalog_entry.catalog0x03)
                catalog_file_offset = catalog_file_offset + 128 * 2
                list_catalog_entry.append(copy.deepcopy(catalog_entry))
            else:
                f_catalog.read(128)
                catalog_file_offset = catalog_file_offset + 128

    return list_catalog_entry


def write_catalog(f_new_catalog, list_catalog_entry):
    pass
    index_catalog = 0
    for catalog_offset in [0x0, 0x4000, 0x8000, 0xc000]:
        buf = 0x0
        if catalog_offset == 0xc000:
            next_block_offset = 0x0
        else:
            next_block_offset = catalog_offset + 0x4000

        if buf == 0:
            f_new_catalog.write(CatalogBlockHeader(catalog_offset, catalog_offset, next_block_offset))
            buf = buf + 128

        while next_block_offset - buf > 128 * 2 and index_catalog < len(list_catalog_entry):
            f_new_catalog.write(list_catalog_entry[index_catalog].catalog0x02)
            f_new_catalog.write(list_catalog_entry[index_catalog].catalog0x03)
            buf = buf + 128 * 2
            index_catalog = index_catalog + 1
            if index_catalog == len(list_catalog_entry):
                break

        for i in range((0x4000 - buf) // 128):
            f_new_catalog.write(CatalogEntry0x00())
            buf = buf + 128


def print_entry(list_catalog_entry):
    epoch_as_filetime = 116444736000000000  # January 1, 1970 as MS file time
    hundreds_of_nanoseconds = 10000000
    index = 0
    for entry in list_catalog_entry:
        dt = datetime.datetime.utcfromtimestamp((entry.catalog0x02.shadow_copy_creation_time - epoch_as_filetime)/hundreds_of_nanoseconds)
        if entry.enable:
            enable_state = "Enable"
        else:
            enable_state = "Disable"
        print("[{0}] {1}, Date: {2}, GUID: {3}".format(index, enable_state, dt, entry.catalog0x02.store_guid))
        index = index + 1


def parse_entry_number(entry_number):
    list_entry_number = []
    for number in entry_number.split(','):
        if not ('-' in number):
            list_entry_number.append(int(number))
        elif '-' in number:
            start, end = number.split('-')
            if int(start) >= int(end):
                exit("Corrupt entry number.")
            for i in range(int(start), int(end) + 1):
                list_entry_number.append(int(i))
        else:
            exit("Corrupt entry number.")
    return list_entry_number


def move_entry_internal(list_catalog_entry, entry_number, destination):
    hundreds_of_nanoseconds = 10000000
    list_result = []
    list_entry_number = parse_entry_number(entry_number)
    list_entry_number.sort()
    # move
    for i in range(0,destination):
        if i in list_entry_number:
            continue
        list_result.append(list_catalog_entry[i])
    for i in list_entry_number:
        list_result.append(list_catalog_entry[i])
    for i in range(destination, len(list_catalog_entry)):
        if i in list_entry_number:
            continue
        list_result.append(list_catalog_entry[i])

    # change meta data
    index = 0
    sequence_number = list_result[0].catalog0x02.sequence_number
    creation_time = list_result[0].catalog0x02.shadow_copy_creation_time
    for entry in list_result:
        entry.catalog0x02.sequence_number = sequence_number - index
        entry.catalog0x02.shadow_copy_creation_time = creation_time - hundreds_of_nanoseconds * 60 * 60 * index
        index = index + 1

    return list_result


def remove_entry_internal(list_catalog_entry, entry_number):
    list_entry_number = parse_entry_number(entry_number)
    list_entry_number.sort(reverse=True)
    for i in list_entry_number:
        del list_catalog_entry[i]


def enable_entry_internal(list_catalog_entry, entry_number):
    list_entry_number = parse_entry_number(entry_number)
    for i in list_entry_number:
        list_catalog_entry[i].enable = True
        list_catalog_entry[i].catalog0x02.catalog_entry_type = 0x2
        list_catalog_entry[i].catalog0x03.catalog_entry_type = 0x3


def disable_entry_internal(list_catalog_entry, entry_number):
    list_entry_number = parse_entry_number(entry_number)
    for i in list_entry_number:
        list_catalog_entry[i].enable = False
        list_catalog_entry[i].catalog0x02.catalog_entry_type = 0x1
        list_catalog_entry[i].catalog0x03.catalog_entry_type = 0x1


def list_entry(args):
    f_catalog = open(args.catalog, "rb")
    list_catalog_entry = read_catalog(f_catalog)
    print_entry(list_catalog_entry)
    f_catalog.close()


def move_entry(args):
    f_catalog = open(args.catalog, "rb")
    f_new_catalog = open(args.catalog + "_move", "wb")
    list_catalog_entry = read_catalog(f_catalog)
    list_result = move_entry_internal(list_catalog_entry, args.entry_number, args.destination)
    print_entry(list_result)
    write_catalog(f_new_catalog, list_result)
    f_catalog.close()
    f_new_catalog.close()


def remove_entry(args):
    f_catalog = open(args.catalog, "rb")
    f_new_catalog = open(args.catalog + "_remove", "wb")
    list_catalog_entry = read_catalog(f_catalog)
    remove_entry_internal(list_catalog_entry, args.entry_number)
    print_entry(list_catalog_entry)
    write_catalog(f_new_catalog, list_catalog_entry)
    f_catalog.close()
    f_new_catalog.close()


def enable_entry(args):
    f_catalog = open(args.catalog, "rb")
    f_new_catalog = open(args.catalog + "_enable", "wb")
    list_catalog_entry = read_catalog(f_catalog)
    enable_entry_internal(list_catalog_entry, args.entry_number)
    print_entry(list_catalog_entry)
    write_catalog(f_new_catalog, list_catalog_entry)
    f_catalog.close()
    f_new_catalog.close()


def disable_entry(args):
    f_catalog = open(args.catalog, "rb")
    f_new_catalog = open(args.catalog + "_disable", "wb")
    list_catalog_entry = read_catalog(f_catalog)
    disable_entry_internal(list_catalog_entry, args.entry_number)
    print_entry(list_catalog_entry)
    write_catalog(f_new_catalog, list_catalog_entry)
    f_catalog.close()
    f_new_catalog.close()


def main():
    parser = argparse.ArgumentParser(description="Manipulate VSS snapshot catalog file. This tool expects output of vss_carver.py.")
    subparsers = parser.add_subparsers(help='sub-command help', title='subcommands')
    # parser.add_argument('--debug', action='store_true', default=False,
    #                     help='debug mode if this flag is set (default: False)')

    # list
    parser_list = subparsers.add_parser('list', help='list -h')
    parser_list.add_argument('catalog', action='store', type=str,
                             help='path to catalog file.')
    parser_list.set_defaults(func=list_entry)

    # move
    parser_move = subparsers.add_parser('move', help='move -h. This manipulation will change several meta data (change shadow copy creation time, etc).')
    parser_move.add_argument('catalog', action='store', type=str,
                             help='path to catalog file.')
    parser_move.add_argument('entry_number', action='store', type=str,
                             help='list of entry numbers to move.')
    parser_move.add_argument('destination', action='store', type=int,
                             help='entry number of destination.')
    parser_move.set_defaults(func=move_entry)

    # remove
    parser_remove = subparsers.add_parser('remove', help='remove -h')
    parser_remove.add_argument('catalog', action='store', type=str,
                               help='path to catalog file.')
    parser_remove.add_argument('entry_number', action='store', type=str,
                               help='list of entry numbers to remove. ex) 2,3,5-8')
    parser_remove.set_defaults(func=remove_entry)

    # enable
    parser_enable = subparsers.add_parser('enable', help='enable -h')
    parser_enable.add_argument('catalog', action='store', type=str,
                               help='path to catalog file.')
    parser_enable.add_argument('entry_number', action='store', type=str,
                               help='list of entry numbers to enable. ex) 2,3,5-8')
    parser_enable.set_defaults(func=enable_entry)

    # disable
    parser_disable = subparsers.add_parser('disable', help='enable -h')
    parser_disable.add_argument('catalog', action='store', type=str,
                                help='path to catalog file.')
    parser_disable.add_argument('entry_number', action='store', type=str,
                                help='list of entry numbers to disable. ex) 2,3,5-8')
    parser_disable.set_defaults(func=disable_entry)

    # offset
    # parser_disable = subparsers.add_parser('disable', help='enable -h')
    # parser_disable.add_argument('catalog', action='store', type=str,
    #                             help='path to catalog file.')
    # parser_disable.add_argument('entry_number', action='store', type=str,
    #                             help='list of entry numbers to disable. ex) 2,3,5-8')
    # parser_disable.set_defaults(func=disable_entry)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
