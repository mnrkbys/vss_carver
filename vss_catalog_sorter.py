#!/usr/bin/env python
#
# vss_catalog_manipulator.py
# Manipulates VSS catalog file that recreated by vss_carver.py.
#
# Copyright (C) 2018-2022 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT
#

import argparse
import copy
import datetime
import io
import os
import struct
import sys
import uuid
from ctypes import (LittleEndianStructure, c_char, c_ubyte, c_uint16, c_uint32,
                    c_uint64, c_wchar, sizeof)
from enum import IntEnum, IntFlag

# import hexdump
import pyewf
import pyvmdk

__VERSION__ = '20221124'
vss_identifier = b'\x6B\x87\x08\x38\x76\xC1\x48\x4E\xB7\xAE\x04\x04\x6E\x6C\xC7\x52'

debug = False


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
        ('store_guid', c_ubyte * 16),
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
        ('store_guid', c_ubyte * 16),
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


class StoreBlockHeader(LittleEndianStructure):
    _fields_ = (
        ('vssid', c_char * 16),
        ('version', c_uint32),
        ('record_type', c_uint32),
        ('relative_block_offset', c_uint64),
        ('current_block_offset', c_uint64),
        ('next_block_offset', c_uint64),
        ('size_info', c_uint64),
        ('unknown', c_char * 72)
    )

    def __init__(self):
        self.vssid = b'\x00'
        self.version = 0x0
        self.record_type = 0x0
        self.relative_block_offset = 0x0
        self.current_block_offset = 0x0
        self.next_block_offset = 0x0
        self.size_info = 0x0
        self.unknown = b'\x00'
        # self.flag_dummy = False


class StoreBlockHeader0x4000(LittleEndianStructure):
    _fields_ = (
        ('vssid', c_char * 16),
        ('version', c_uint32),
        ('record_type', c_uint32),
        ('relative_block_offset', c_uint64),
        ('current_block_offset', c_uint64),
        ('next_block_offset', c_uint64),
        ('size_info', c_uint64),
        ('unknown', c_char * 72),
        ('data', c_char * (0x4000 - 128))
    )

    def __init__(self):
        self.unknown = b'\x00'
        self.data = b'\x00'


# StoreBlockHeader.record_type = 4
class StoreInformation(LittleEndianStructure):
    _fields_ = (
        ('unknown_identifier', c_char * 16),
        ('shadow_copy_identifier', c_char * 16),
        ('shadow_copy_set_identifier', c_char * 16),
        ('snapshot_context', c_uint32),
        ('unknown1', c_uint32),
        ('attribute_flags', c_uint32),
        ('unknown2', c_uint32),
        ('operating_machine_string_data', c_ubyte * (0x4000 - 128 - 64))
    )


# StoreBlockHeader.record_type = 3
class StoreBlockListEntry(LittleEndianStructure):
    _fields_ = (
        ('original_data_block_offset', c_uint64),
        ('relative_store_data_block_offset', c_uint64),
        ('store_data_block_offset', c_uint64),
        ('flags', c_uint32),
        ('allocation_bitmap', c_uint32)
    )


class MftEntryFlags(IntFlag):
    FILE_RECORD_SEGMENT_IN_USE = 0x0001
    MFT_RECORD_IN_USE          = 0x0001
    FILE_NAME_INDEX_PRESENT    = 0x0002
    MFT_RECORD_IS_DIRECTORY    = 0x0002
    MFT_RECORD_IN_EXTEND       = 0x0004
    MFT_RECORD_IS_VIEW_INDEX   = 0x0008


class FileReference(LittleEndianStructure):
    _fields_ = (
        # ('mft_entry_index', c_ubyte * 6),
        # ('sequence_number', c_uint16)
        ('file_reference', c_uint64),
    )

    def __getattr__(self, name):
        if name == 'mft_entry_index':
            return self.file_reference & 0x0000FFFFFFFFFFFF
        elif name == 'sequence_number':
            return self.file_reference >> 48
        # else:
        #     return super().__getattr__(name)


class MftEntryHeader(LittleEndianStructure):
    _fields_ = (
        ('signature', c_char * 4),
        ('fixup_values_offset', c_uint16),
        ('number_of_fixup_values', c_uint16),
        ('logfile_sequence_number', c_uint64),
        ('sequence_number', c_uint16),
        ('reference_count', c_uint16),
        ('attribute_offset', c_uint16),
        ('entry_flags', c_uint16),
        ('used_entry_size', c_uint32),
        ('total_entry_size', c_uint32),
        ('base_record_file_reference', FileReference),
        ('first_available_attribute_id', c_uint16),
        ('unknown', c_uint16),
        ('index', c_uint32)  # MFT Entry ID (= inode)
    )

    def print(self):
        print("MFT Entry Header")
        print("MFT entry index and sequence number:")
        print("\tMFT entry index: 0x{:x}".format(self.index))
        print("\tSequence number: 0x{:x}".format(self.sequence_number))
        print("Base record file reference:")
        print("\tMFT entry index: 0x{:x}".format(self.base_record_file_reference.mft_entry_index))
        print("\tSequence number: 0x{:x}".format(self.base_record_file_reference.sequence_number))

class NonResidentFlag(IntFlag):
    RESIDENT_FORM    = 0x0
    NONRESIDENT_FORM = 0x1


class MftAttributeHeader(LittleEndianStructure):
    _fields_ = (
        ('attribute_type', c_uint32),
        ('size', c_uint32),
        ('non_resident_flag', c_ubyte),
        ('name_size', c_ubyte),
        ('name_offset', c_uint16),
        ('attribute_data_flags', c_uint16),
        ('attribute_id', c_uint16)
    )


class ResidentMftAttribute(LittleEndianStructure):
    _fields_ = (
        ('data_size', c_uint32),
        ('data_offset', c_uint16),
        ('indexed_flag', c_ubyte),
        ('padding', c_ubyte)
    )


class AttributeTypes(IntEnum):
    UNUSED               = 0x00000000
    STANDARD_INFORMATION = 0x00000010
    FILE_NAME            = 0x00000030
    DATA                 = 0x00000080
    END_OF_ATTRIBUTE     = 0xFFFFFFFF


class StandardInformationAttribute(LittleEndianStructure):
    _fields_ = (
        ('creation_timestamp', c_uint64),
        ('modification_timestamp', c_uint64),
        ('mft_entry_modification_timestamp', c_uint64),
        ('access_timestamp', c_uint64),
        ('file_attribute_flags', c_uint32),
        ('unknown1', c_uint32),
        ('unknown2', c_uint32),
        ('unknown3', c_uint32),
        ('owner_id', c_uint32),
        ('security_descriptor_id', c_uint32),
        ('quota_charged', c_uint64),
        ('update_sequence_number', c_uint64)
    )

    def print(self):
        print("$STANDARD_INFORMATION")
        print("Create: {}".format(filetime_timestamp(self.creation_timestamp)))
        print("Modify: {}".format(filetime_timestamp(self.modification_timestamp)))
        # Sometimes, an error is occurred. Commented out temporally.
        print("MFT Modify (hex): 0x{:x}".format(self.mft_entry_modification_timestamp))
        print("MFT Modify: {}".format(filetime_timestamp(self.mft_entry_modification_timestamp)))
        print("Access: {}".format(filetime_timestamp(self.access_timestamp)))
        print("Update Sequence Number: 0x{:x}".format(self.update_sequence_number))


class NameSpace(IntEnum):
    POSIX          = 0
    FILE_NAME_NTFS = 1
    WINDOWS        = 1
    FILE_NAME_DOS  = 2
    DOS            = 2
    DOS_WINDOWS    = 3


class FileNameAttribute(LittleEndianStructure):
    _fields_ = (
        # ('parent_file_reference', c_uint64),
        ('parent_file_reference', FileReference),
        ('creation_timestamp', c_uint64),
        ('modification_timestamp', c_uint64),
        ('mft_entry_modification_timestamp', c_uint64),
        ('access_timestamp', c_uint64),
        ('allocated_file_size', c_uint64),
        ('file_size', c_uint64),
        ('file_attribute_flags', c_uint32),
        ('extended_data', c_uint32),
        ('name_string_size', c_ubyte),
        ('namespace', c_ubyte),
        ('name_string', c_ubyte * 0x1FE)  # 0x1FE = 0xFF * 2
    )

    def print(self):
        print("$FILE_NAME")
        print("Parent file reference:")
        print("\tMFT entry index: 0x{:x}".format(self.parent_file_reference.mft_entry_index))
        print("\tSequence number: 0x{:x}".format(self.parent_file_reference.sequence_number))
        print("Namespace: {}".format(self.namespace))
        name_string = struct.unpack_from("<{}s".format(self.name_string_size*2), bytes(self.name_string[:self.name_string_size*2]))[0].decode(encoding='utf-16')
        try:
            print("Name: {}".format(name_string))
        except UnicodeEncodeError:
            print("Name: {}".format(bytes(self.name_string[:self.name_string_size*2])))
        print("Create: {}".format(filetime_timestamp(self.creation_timestamp)))
        print("Modify: {}".format(filetime_timestamp(self.modification_timestamp)))
        print("MFT Modify: {}".format(filetime_timestamp(self.mft_entry_modification_timestamp)))
        print("Access: {}".format(filetime_timestamp(self.access_timestamp)))


class BaseFileDirElement(LittleEndianStructure):
    def __init__(self, mft_entry_header=MftEntryHeader(), standard_information_attribute=StandardInformationAttribute(), file_name_attribute=FileNameAttribute()):
        self.mft_entry_header = mft_entry_header
        self.standard_information_attribute = standard_information_attribute
        self.file_name_attribute = file_name_attribute

    def print(self):
        self.mft_entry_header.print()
        self.standard_information_attribute.print()
        self.file_name_attribute.print()


class BaseFileDirCollection(object):
    def __init__(self, mft, base_file_directories, base_file_records, found_all_records):
        self.mft = mft
        self.base_file_directories = base_file_directories
        self.base_file_records = base_file_records
        self.found_all_records = found_all_records


def dbg_print(msg):
    if debug:
        print(msg)


def readinto_ctypes_struct(disk_image, struct_obj):
    data = disk_image.read(sizeof(struct_obj))
    return io.BytesIO(data).readinto(struct_obj)


def read_catalog(f_catalog):
    list_catalog_entry = []
    catalog_block_header = CatalogBlockHeader()
    catalog_entry = CatalogEntry()
    catalog_file_offset = 0

    for catalog_block_offset in (0x0, 0x4000, 0x8000, 0xc000):
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
                if all(x == y for x, y in zip(catalog_entry.catalog0x02.store_guid, catalog_entry.catalog0x03.store_guid)):
                    list_catalog_entry.append(copy.deepcopy(catalog_entry))
                else:
                    guid = bytearray(len(catalog_entry.catalog0x02.store_guid))
                    for i in range(len(catalog_entry.catalog0x02.store_guid)):
                        guid[i] = catalog_entry.catalog0x02.store_guid[i]
                    print("Catalog Entry Type 0x02 GUID: {0}".format(str(uuid.UUID(bytes_le=bytes(guid)))))
                    for i in range(len(catalog_entry.catalog0x03.store_guid)):
                        guid[i] = catalog_entry.catalog0x03.store_guid[i]
                    print("Catalog Entry Type 0x03 GUID: {0}".format(str(uuid.UUID(bytes_le=bytes(guid)))))
                    exit(" Catalog GUID doesn't match.")
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
    index_catalog = 0
    for catalog_offset in (0x0, 0x4000, 0x8000, 0xc000):
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


def update_shadow_copy_creation_time(timestamp_candidates):
    sorted_list_catalog_entry = []
    for ts in sorted(timestamp_candidates.keys(), reverse=True):
        timestamp_candidates[ts].catalog0x02.shadow_copy_creation_time = ts
        sorted_list_catalog_entry.append(timestamp_candidates[ts])

    return sorted_list_catalog_entry


def filetime_timestamp(filetime):
    epoch_as_filetime = 116444736000000000  # January 1, 1970 as MS file time
    hundreds_of_nanoseconds = 10000000
    if filetime >= epoch_as_filetime:
        return datetime.datetime.utcfromtimestamp((filetime - epoch_as_filetime)/hundreds_of_nanoseconds)
    else:
        return ('N/A (0x{:x})').format(filetime)


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

        guid = bytearray(len(entry.catalog0x02.store_guid))
        for i in range(len(entry.catalog0x02.store_guid)):
            guid[i] = entry.catalog0x02.store_guid[i]
        print("[{0}] {1}, Date: {2}, GUID: {3}".format(index, enable_state, dt, str(uuid.UUID(bytes_le=bytes(guid)))))
        index = index + 1


def get_machine_string(list_catalog_entry, f_store):
    for catalog_entry in list_catalog_entry:
        f_store.seek(catalog_entry.catalog0x03.store_header_offset)
        store_block_header = StoreBlockHeader()
        readinto_ctypes_struct(f_store, store_block_header)
        if store_block_header.version == 0x1 and store_block_header.record_type == 0x4:
            store_information = StoreInformation()
            readinto_ctypes_struct(f_store, store_information)
            operating_machine_string_size = struct.unpack_from("<H", store_information.operating_machine_string_data, 0)[0]
            operating_machine_string = struct.unpack_from("<{}s".format(operating_machine_string_size), store_information.operating_machine_string_data, 2)[0].decode(encoding='utf-16')
            service_machine_string_size = struct.unpack_from("<H", store_information.operating_machine_string_data, 2 + operating_machine_string_size)[0]
            service_machine_string = struct.unpack_from("<{}s".format(service_machine_string_size), store_information.operating_machine_string_data, 2 + operating_machine_string_size + 2)[0].decode(encoding='utf-16')
            yield operating_machine_string, service_machine_string
        else:
            yield 'Not found store block header.', 'Not found store block header.'


def mini_hexdump(data):
    for i, x in enumerate(data, 1):
        print(f"{x:02x}", end=' ')
        if i % 20 == 0:
            print()
        elif i % 10 == 0:
            print(end=' ')

    print('\n')


def get_store_data_block_data(catalog_entry, f_store, f_disk_image, vol_offset):
    f_store.seek(catalog_entry.catalog0x03.store_block_list_offset)
    while True:
        store_block_header = StoreBlockHeader()
        readinto_ctypes_struct(f_store, store_block_header)
        if store_block_header.version == 0x1 and store_block_header.record_type == 0x3:
            store_data_block_offset = 0
            while store_data_block_offset < 0x4000 - 128:
                store_block_list_entry = StoreBlockListEntry()
                readinto_ctypes_struct(f_store, store_block_list_entry)
                f_disk_image.seek(vol_offset + store_block_list_entry.store_data_block_offset)
                # f_disk_image.seek(vol_offset + store_block_list_entry.original_data_block_offset)
                store_data_block_data = f_disk_image.read(0x4000)
                data_offset = 0
                while data_offset < 0x4000:
                    if store_data_block_data[data_offset:data_offset+4] == b'FILE':
                        # 4K bytes MFT record should be supported.
                        yield vol_offset + store_block_list_entry.store_data_block_offset + data_offset, store_data_block_data[data_offset:data_offset+1024]
                    data_offset += 1024

                store_data_block_offset += sizeof(StoreBlockListEntry)

        dbg_print("store_block_header.next_block_offset: 0x{:x}".format(store_block_header.next_block_offset))
        if store_block_header.next_block_offset == 0x0:
            break
        else:
            f_store.seek(store_block_header.next_block_offset)


def parse_basefile_path(base_file_path):
    base_file_directories = {}
    if os.name == 'nt':
        base_file_path = os.path.abspath(base_file_path).replace('\\', '/')[2:]
    elif os.name == 'posix':
        base_file_path = os.path.abspath(base_file_path.replace('\\', '/'))
    else:
        exit("Unsupported platfom: {}".format(os.name))

    for path in base_file_path.split('/'):
        if path == '':
            path = '.'  # root directory name
        base_file_directories[path] = []

    return base_file_directories


def check_base_file_directories(base_file_directories):
    base_file_dir_element_with_latest_sequence_number = {}
    for name_string in base_file_directories.keys():
        base_file_dir_element_with_latest_sequence_number[name_string] = BaseFileDirElement(None, None, None)

    dir_depth = 0
    for name_string, base_file_dir_elements in base_file_directories.items():
        latest_sequence_number = -1
        for base_file_dir_element in base_file_dir_elements:
            if dir_depth == 0:
                # MFT entry index of root directory = 5
                if name_string == '.' and base_file_dir_element.mft_entry_header.index == 5:
                    if base_file_dir_element.mft_entry_header.sequence_number > latest_sequence_number:
                        base_file_dir_element_with_latest_sequence_number[name_string] = base_file_dir_element
                        latest_sequence_number = base_file_dir_element.mft_entry_header.sequence_number
                        if debug:
                            print("*" * 50)
                            print("name_string: {}".format(name_string))
                            print("dir_depth: {}".format(dir_depth))
                            base_file_dir_element.print()

            elif dir_depth >= 1:
                parent_dir = list(base_file_directories.keys())[dir_depth-1]
                parent_mft_entry_index = base_file_dir_element_with_latest_sequence_number[parent_dir].mft_entry_header.index
                if base_file_dir_element.file_name_attribute.parent_file_reference.mft_entry_index == parent_mft_entry_index:
                    if base_file_dir_element.mft_entry_header.sequence_number > latest_sequence_number:
                        base_file_dir_element_with_latest_sequence_number[name_string] = base_file_dir_element
                        latest_sequence_number = base_file_dir_element.mft_entry_header.sequence_number
                        if debug:
                            print("*" * 50)
                            print("name_string: {}".format(name_string))
                            print("dir_depth: {}".format(dir_depth))
                            base_file_dir_element.print()

        if base_file_dir_element_with_latest_sequence_number[name_string].mft_entry_header is not None:
            dir_depth += 1

    dbg_print("dir_depth: {}".format(dir_depth))
    dbg_print("len(base_file_directories): {}".format(len(base_file_directories)))
    if dir_depth == len(base_file_directories):
        return True, base_file_dir_element_with_latest_sequence_number
    else:
        return False, base_file_dir_element_with_latest_sequence_number


def analyze_mft_record(store_data_block_data, base_file_directories):
    base_file = list(base_file_directories.keys())[-1]

    # try:
    mft_entry_header = MftEntryHeader()
    io.BytesIO(store_data_block_data).readinto(mft_entry_header)
    data_offset = mft_entry_header.attribute_offset

    # https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#31-the-metadata-files
    if bytes(mft_entry_header.signature) == b'FILE' and mft_entry_header.entry_flags & MftEntryFlags.MFT_RECORD_IN_USE and mft_entry_header.total_entry_size in (1024, 4096):
        dbg_print('*' * 50)
        dbg_print("MFT entry size: {}".format(mft_entry_header.total_entry_size))
        mft_attribute_header = MftAttributeHeader()
        io.BytesIO(store_data_block_data[data_offset:]).readinto(mft_attribute_header)

        while data_offset < mft_entry_header.total_entry_size and mft_attribute_header.attribute_type != AttributeTypes.END_OF_ATTRIBUTE:
            if mft_attribute_header.attribute_type in (AttributeTypes.STANDARD_INFORMATION, AttributeTypes.FILE_NAME, AttributeTypes.DATA):
                dbg_print('-' * 50)
                dbg_print("data_offset: 0x{:x}".format(data_offset))
                if mft_attribute_header.non_resident_flag == NonResidentFlag.RESIDENT_FORM:
                    resident_mft_attribute = ResidentMftAttribute()
                    io.BytesIO(store_data_block_data[data_offset+sizeof(MftAttributeHeader):]).readinto(resident_mft_attribute)

                    if mft_attribute_header.attribute_type == AttributeTypes.STANDARD_INFORMATION:
                        standard_information_attribute = StandardInformationAttribute()
                        io.BytesIO(store_data_block_data[data_offset+resident_mft_attribute.data_offset:data_offset+resident_mft_attribute.data_offset+resident_mft_attribute.data_size]).readinto(standard_information_attribute)
                        if debug:
                            standard_information_attribute.print()

                    elif mft_attribute_header.attribute_type == AttributeTypes.FILE_NAME:
                        file_name_attribute = FileNameAttribute()
                        io.BytesIO(store_data_block_data[data_offset+resident_mft_attribute.data_offset:data_offset+resident_mft_attribute.data_offset+resident_mft_attribute.data_size]).readinto(file_name_attribute)
                        if debug:
                            file_name_attribute.print()

                        name_string = struct.unpack_from("<{}s".format(file_name_attribute.name_string_size*2), bytes(file_name_attribute.name_string[:file_name_attribute.name_string_size*2]))[0].decode(encoding='utf-16')

                        if mft_entry_header.entry_flags & MftEntryFlags.MFT_RECORD_IS_DIRECTORY:
                            if name_string in list(base_file_directories.keys())[:-1]:
                                base_file_directories[name_string].append(BaseFileDirElement(mft_entry_header, standard_information_attribute, file_name_attribute))
                        else:
                            if name_string == list(base_file_directories.keys())[-1]:
                                base_file_directories[name_string].append(BaseFileDirElement(mft_entry_header, standard_information_attribute, file_name_attribute))
                        # print(base_file_directories)
                        # if check_base_file_directories(base_file_directories):
                        #     yield standard_information_attribute.modification_timestamp

                        if name_string == base_file:
                            # MACB timestamps of $FILE_NAME are not updated, so use the modification timestamp of $STANDARD_INFORMATION instead of it.
                            yield standard_information_attribute.modification_timestamp

                    elif mft_attribute_header.attribute_type == AttributeTypes.DATA:
                        dbg_print("$DATA")
                        # Do nothing.
                        pass

                else:
                    dbg_print("Attribute type: 0x{:x}".format(mft_attribute_header.attribute_type))
                    dbg_print("Does not support NONRESIDENT_FORM")
                    # Do nothing.
                    pass

            else:
                if mft_attribute_header.attribute_type != AttributeTypes.UNUSED:
                    dbg_print('-' * 50)
                    dbg_print("Unsupported attribute type: 0x{:x}".format(mft_attribute_header.attribute_type))

            data_offset += mft_attribute_header.size
            io.BytesIO(store_data_block_data[data_offset:]).readinto(mft_attribute_header)

    # except:
    #     print("Something is wrong... Check MFT entry below:")
    #     mini_hexdump(store_data_block_data)
    #     # exit


def main():
    global debug

    # Parse arguments
    parser = argparse.ArgumentParser(prog='vss_catalog_sorter', description="Carve and rebuild VSS snapshot catalog and store from disk image.")
    parser.add_argument('-t', '--disktype', action='store', type=str,
                        help='Specify a disk type: E01, VMDK, RAW')
    parser.add_argument('-o', '--offset', action='store', type=int,
                        help='A start offset of volume in disk image.')
    parser.add_argument('-i', '--image', action='store', type=str,
                        help='Specify a disk image to analyze.')
    parser.add_argument('-c', '--catalog', type=str,
                        help='Specify a catalog file.')
    parser.add_argument('-s', '--store', type=str,
                        help='Specify a store file.')
    parser.add_argument('-m', '--mft', type=str,
                        help='Specify an exported $MFT file.')
    parser.add_argument('-b', '--basefile', type=str, default='/Windows/System32/winevt/Logs/System.evtx',
                        help='Specify the file on which to base the sorting (default: /Windows/System32/winevt/Logs/System.evtx)')
    # parser.add_argument('-b', '--basefile', type=str, default='System.evtx',
    #                     help='Specify the file on which to base the sorting (default: System.evtx)')
    parser.add_argument('-f', '--force', action='store_true', default=False,
                        help='Enable to overwrite a catalog file and a store file (default: False)')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Debug mode if this flag is set (default: False)')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__VERSION__))
    args = parser.parse_args()

    print('vss_catalog_sorter {}'.format(__VERSION__))

    # Check requirement of arguments
    if None in (args.disktype, args.image, args.offset, args.catalog, args.store, args.basefile):
        exit("too few arguments.")

    debug = args.debug

    if os.path.exists(os.path.abspath(args.image)):
        if args.disktype.upper() == 'E01':
            disk_filenames = pyewf.glob(args.image)
            disk_image = pyewf.handle()
            disk_image.open(disk_filenames)
        elif args.disktype.upper() == 'VMDK':
            disk_image = pyvmdk.handle()
            disk_image.open(args.image)
            disk_image.open_extent_data_files()
        elif args.disktype.upper() == 'RAW':
            disk_image = open(args.image, "rb")
        else:
            exit("{} is not supported disk type.".format(args.disktype))
    else:
        exit("{} does not exist.".format(args.image))

    if not os.path.exists(os.path.abspath(args.catalog)):
        exit("{} does not exist.".format(args.catalog))

    if not os.path.exists(os.path.abspath(args.store)):
        exit("{} does not exist.".format(args.store))

    if args.mft and not os.path.exists(os.path.abspath(args.mft)):
        exit("{} does not exist.".format(args.mft))

    sorted_catalog = args.catalog + '_sorted'
    if not args.force and os.path.exists(os.path.abspath(sorted_catalog)):
        exit("{} already exists.".format(sorted_catalog))

    if args.basefile[0] not in ('\\', '/'):
        exit('"--basefile" opstion should be started with "\\" or "/".')

    f_catalog = open(args.catalog, 'rb')
    f_store = open(args.store, 'rb')
    f_sorted_catalog = open(sorted_catalog, 'wb')
    if args.mft:
        f_mft = open(args.mft, 'rb')

    list_catalog_entry = read_catalog(f_catalog)
    print("Loaded catalog list:")
    print_entry(list_catalog_entry)

    # for operating_machine_string, service_machine_string in get_machine_string(list_catalog_entry, f_store):
    #     print("Operating machine: {}, Service machine: {}".format(operating_machine_string, service_machine_string))

    base_file_directories_collections = []

    if f_mft:
        base_file_directories_mft = parse_basefile_path(args.basefile)
        print("=" * 60)
        print("Analyzing $MFT...")
        mft_record = f_mft.read(1024)
        while mft_record != b'':
            for _ in analyze_mft_record(mft_record, base_file_directories_mft):
                pass
            mft_record = f_mft.read(1024)

        result, base_file_records = check_base_file_directories(base_file_directories_mft)
        if result:
            print("Found base file entry: {}".format(args.basefile))
        else:
            print("Could not found base file entry: {}".format(args.basefile))

        base_file_directories_collections.append(BaseFileDirCollection(True, base_file_directories_mft, base_file_records, result))

    else:
        base_file_directories_mft = parse_basefile_path(args.basefile)
        base_file_records = {}
        for name_string in base_file_directories_mft.keys():
            base_file_records[name_string] = BaseFileDirElement(None, None, None)
        base_file_directories_collections.append(BaseFileDirCollection(True, base_file_directories_mft, base_file_records, False))

    # processed_physical_data_offset = {}
    timestamp_candidates = {}
    for catalog_entry in list_catalog_entry:
        base_file_directories = parse_basefile_path(args.basefile)
        # dbg_print("~*~" * 20)
        # dbg_print("catalog_entry.catalog0x03.store_block_list_offset: 0x{:x}".format(catalog_entry.catalog0x03.store_block_list_offset))
        print("+" * 60)
        print("catalog_entry.catalog0x03.store_block_list_offset: 0x{:x}".format(catalog_entry.catalog0x03.store_block_list_offset))
        for physical_data_offset, store_data_block_data in get_store_data_block_data(catalog_entry, f_store, disk_image, args.offset):
            # if physical_data_offset not in processed_physical_data_offset.keys():
            #     processed_physical_data_offset[physical_data_offset] = 1
            # else:
            #     processed_physical_data_offset[physical_data_offset] += 1

            dbg_print("=" * 50)
            dbg_print("MFT record offset of base file: 0x{:x}".format(physical_data_offset))
            for timestamp in analyze_mft_record(store_data_block_data, base_file_directories):
            # for timestamp in analyze_mft_record(store_data_block_data, args.basefile):
                timestamp_candidates[timestamp] = catalog_entry

        # for path, base_file_dir_elements in base_file_directories.items():
        #     for base_file_dir_element in base_file_dir_elements:
        #         print("---" * 20)
        #         base_file_dir_element.print()

        result, base_file_records = check_base_file_directories(base_file_directories)
        if result:
            print("Found base file entry: {}".format(args.basefile))
        else:
            print("Could not found base file entry: {}".format(args.basefile))

        base_file_directories_collections.append(BaseFileDirCollection(False, base_file_directories, base_file_records, result))

    # debug = True
    collection_num = 0
    for base_file_directories_collection in base_file_directories_collections:
        lacking_path = []
        if not base_file_directories_collection.mft and not base_file_directories_collection.found_all_records:
            for name_string, base_file_dir_element in base_file_directories_collection.base_file_records.items():
                # print("base_file_dir_element:")
                # base_file_dir_element.print()
                if base_file_dir_element.mft_entry_header is None:
                    # count = collection_num - 1
                    # while count >= 0:
                    #     temp_directories = copy.deepcopy(base_file_directories_collection.base_file_directories)
                    #     temp_directories[name_string] = base_file_directories_collections[count].base_file_directories[name_string]
                    #     for name, elements in temp_directories.items():
                    #         print("#" * 60)
                    #         print("Name: {}".format(name))
                    #         for element in elements:
                    #             element.print()
                    #     result, base_file_records = check_base_file_directories(temp_directories)
                    #     if result:
                    #         base_file_directories_collection.base_file_records = base_file_records
                    #         break
                    #     else:
                    #         count -= 1
                    lacking_path.append(name_string)

                print("collection_num: {}".format(collection_num))
                print("lacking_path: {}\n".format(lacking_path))

            result = False
            temp_directories = copy.deepcopy(base_file_directories_collection.base_file_directories)
            for path in lacking_path:
                # temp_directories = None
                prev_num = collection_num - 1
                while prev_num >= 0:
                    if base_file_directories_collections[prev_num].base_file_directories[path] is not None:
                        temp_directories[path] = base_file_directories_collections[prev_num].base_file_directories[path]

                        result, base_file_records = check_base_file_directories(temp_directories)
                        print("*" * 60)
                        print("result: {}".format(result))
                        if result:
                            base_file_directories_collection.base_file_records = base_file_records
                            # print("Fixed base_file_records: {}".format(base_file_directories_collection.base_file_records))
                            print("Fixed base_file_records:")
                            for path, element in base_file_directories_collection.base_file_records.items():
                                print("path: {}".format(path))
                                element.print()
                                print("\n")

                            break

                    prev_num -= 1

                if result:
                    break

                # if temp_directories:
                #     result, base_file_records = check_base_file_directories(temp_directories)
                #     print("*" * 60)
                #     print("result: {}".format(result))

                #     # base_file_records[path].print()
                #     if result:
                #         base_file_directories_collection.base_file_records = base_file_records
                #         print("Fixed base_file_records: {}".format(base_file_directories_collection.base_file_records))

        collection_num += 1

    if debug:
        print("~" * 50)
        for ts, catalog_entry in timestamp_candidates.items():
            print("Timestamp candidate: 0x{:x} ({})".format(ts, filetime_timestamp(ts)))
            print_entry([catalog_entry])

    updated_list_catalog_entry = update_shadow_copy_creation_time(timestamp_candidates)
    write_catalog(f_sorted_catalog, updated_list_catalog_entry)
    print("-=" * 40)
    print("Sorted catalog list")
    print_entry(updated_list_catalog_entry)

    f_store.close()
    f_catalog.close()
    f_sorted_catalog.close()
    disk_image.close()
    if f_mft:
        f_mft.close()


if __name__ == "__main__":
    if sys.version_info[0:2] >= (3, 7):
        sys.exit(main())
    else:
        sys.exit("This script needs greater than or equal to Python 3.7")
