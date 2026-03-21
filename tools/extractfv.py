#!/usr/bin/env python3
"""
Extract LinuxLoader.efi from Qualcomm ABL.img
Supports LZMA-compressed nested Firmware Volumes.
"""

import struct
import sys
import os
import lzma

EFI_FV_SIGNATURE = b'_FVH'

# Section Types
EFI_SECTION_COMPRESSION           = 0x01
EFI_SECTION_GUID_DEFINED          = 0x02
EFI_SECTION_PE32                  = 0x10
EFI_SECTION_TE                    = 0x12
EFI_SECTION_USER_INTERFACE        = 0x15
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_RAW                   = 0x19

# Compression Types
EFI_NOT_COMPRESSED    = 0x00
EFI_STANDARD_COMPRESSION = 0x01

# Known LZMA GUID-defined section GUIDs
LZMA_COMPRESS_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'

FFS_TYPE_NAMES = {
    0x01: 'RAW', 0x02: 'FREEFORM', 0x03: 'SECURITY_CORE',
    0x04: 'PEI_CORE', 0x05: 'DXE_CORE', 0x06: 'PEIM',
    0x07: 'DRIVER', 0x08: 'COMBINED_PEIM_DRIVER', 0x09: 'APPLICATION',
    0x0A: 'MM', 0x0B: 'FV_IMAGE',
}

SECTION_TYPE_NAMES = {
    0x01: 'COMPRESSION', 0x02: 'GUID_DEFINED', 0x10: 'PE32',
    0x12: 'TE', 0x15: 'USER_INTERFACE', 0x17: 'FV_IMAGE', 0x19: 'RAW',
}

def read_guid(data, offset):
    if offset + 16 > len(data):
        return None
    d1, d2, d3 = struct.unpack_from('<IHH', data, offset)
    d4 = data[offset + 8:offset + 16]
    return (f'{d1:08x}-{d2:04x}-{d3:04x}-'
            f'{d4[0]:02x}{d4[1]:02x}-'
            + ''.join(f'{b:02x}' for b in d4[2:8]))

def align_up(offset, alignment):
    return (offset + alignment - 1) & ~(alignment - 1)

def get_section_size(data, offset):
    if offset + 4 > len(data):
        return 0, 4
    s = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)
    if s == 0xFFFFFF:
        if offset + 8 <= len(data):
            return struct.unpack_from('<I', data, offset + 4)[0], 8
        return 0, 4
    return s, 4

def get_ffs_size(data, offset):
    if offset + 24 > len(data):
        return 0, 24
    attrs = data[offset + 19]
    s = data[offset + 20] | (data[offset + 21] << 8) | (data[offset + 22] << 16)
    if s == 0xFFFFFF and (attrs & 0x01):
        if offset + 32 <= len(data):
            return struct.unpack_from('<Q', data, offset + 24)[0], 32
        return 0, 24
    return s, 24

def try_lzma_decompress(data):
    """尝试多种方式解压 LZMA 数据"""
    # 方式1: 标准 LZMA (5 byte props + 8 byte size + compressed)
    if len(data) >= 13 and data[0] == 0x5D:
        try:
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            result = decompressor.decompress(data)
            return result
        except lzma.LZMAError:
            pass

    # 方式2: raw LZMA stream with properties
    if len(data) >= 5:
        try:
            # 构造 LZMA alone header
            props = data[:5]  # 5 bytes: lc/lp/pb + dict size
            # 尝试从后续字段读取 uncompressed size
            if len(data) >= 13:
                uncomp_size = struct.unpack_from('<Q', data, 5)[0]
                header = props + struct.pack('<Q', uncomp_size)
                compressed = data[13:]
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
                result = decompressor.decompress(header + compressed)
                return result
        except (lzma.LZMAError, struct.error):
            pass

    # 方式3: EFI 风格 LZMA (直接 raw stream, props 在 GUID section 里)
    for skip in [0, 5, 9, 13]:
        if skip >= len(data):
            continue
        try:
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            result = decompressor.decompress(data[skip:])
            return result
        except lzma.LZMAError:
            pass

    # 方式4: xz
    try:
        return lzma.decompress(data)
    except lzma.LZMAError:
        pass

    return None

class EfiExtractor:
    def __init__(self, data):
        self.data = data
        self.results = []  # (name, guid, pe_data)

    def run(self):
        print(f'文件大小: {len(self.data)} bytes (0x{len(self.data):X})\n')
        self._scan_and_parse(self.data, 0, 0)

    def _scan_and_parse(self, buf, base, depth):
        """在 buf 中扫描 FV 并解析"""
        off = 0
        found = False
        while off < len(buf) - 0x38:
            pos = buf.find(EFI_FV_SIGNATURE, off)
            if pos == -1:
                break
            fv_start = pos - 0x28
            if fv_start < 0:
                off = pos + 4
                continue
            try:
                fv_length = struct.unpack_from('<Q', buf, fv_start + 0x20)[0]
                sig = buf[fv_start + 0x28:fv_start + 0x2C]
                hdr_len = struct.unpack_from('<H', buf, fv_start + 0x30)[0]
                if (sig == EFI_FV_SIGNATURE
                        and 0x48 <= hdr_len <= 0x200
                        and 0 < fv_length <= len(buf) - fv_start):
                    self._parse_fv(buf, fv_start, fv_length, hdr_len, depth)
                    found = True
            except struct.error:
                pass
            off = pos + 4
        return found

    def _parse_fv(self, buf, fv_start, fv_length, fv_hdr_len, depth):
        prefix = '  ' * depth
        print(f'{prefix}[FV] @ 0x{fv_start:08X}  size=0x{fv_length:X}')

        offset = align_up(fv_start + fv_hdr_len, 8)
        fv_end = fv_start + fv_length

        while offset + 24 <= fv_end:
            if all(b == 0xFF for b in buf[offset:offset + 24]):
                offset += 8
                continue

            guid = read_guid(buf, offset)
            if guid is None:
                break

            ffs_size, ffs_hdr = get_ffs_size(buf, offset)
            ffs_type = buf[offset + 18]

            if ffs_size < ffs_hdr or offset + ffs_size > fv_end:
                break

            type_name = FFS_TYPE_NAMES.get(ffs_type, f'0x{ffs_type:02X}')

            # 解析 sections
            sections = self._parse_sections(buf, offset + ffs_hdr, offset + ffs_size, depth + 1)
            name = self._get_ui_name(buf, sections)
            name_str = f"  name='{name}'" if name else ''
            print(f'{prefix}  [FFS] {guid}  {type_name}{name_str}')

            # 提取 PE32
            pe = self._get_pe32(buf, sections)
            if pe:
                self.results.append((name, guid, pe))
                if name:
                    print(f'{prefix}    -> PE32 ({len(pe)} bytes)')

            offset = align_up(offset + ffs_size, 8)

    def _parse_sections(self, buf, start, end, depth):
        """递归解析 sections"""
        sections = []
        offset = start

        while offset + 4 <= end:
            offset = align_up(offset, 4)
            if offset + 4 > end:
                break

            sec_size, sec_hdr = get_section_size(buf, offset)
            if sec_size < sec_hdr or sec_size == 0 or offset + sec_size > end:
                break

            sec_type = buf[offset + 3]
            sec = {
                'type': sec_type,
                'offset': offset,
                'size': sec_size,
                'hdr_size': sec_hdr,
            }
            sections.append(sec)

            type_name = SECTION_TYPE_NAMES.get(sec_type, f'0x{sec_type:02X}')
            prefix = '  ' * depth

            if sec_type == EFI_SECTION_COMPRESSION:
                self._handle_compression_section(buf, sec, sections, depth)

            elif sec_type == EFI_SECTION_GUID_DEFINED:
                self._handle_guid_defined_section(buf, sec, sections, depth)

            elif sec_type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
                # 内容是一个完整的 FV
                data_off = offset + sec_hdr
                data_size = sec_size - sec_hdr
                fv_data = buf[data_off:data_off + data_size]
                self._scan_and_parse(fv_data, 0, depth + 1)

            offset += sec_size

        return sections

    def _handle_compression_section(self, buf, sec, sections, depth):
        """处理压缩 section"""
        offset = sec['offset']
        sec_hdr = sec['hdr_size']
        sec_size = sec['size']

        if sec_hdr + 5 > sec_size:
            return

        data_off = offset + sec_hdr
        uncomp_len = struct.unpack_from('<I', buf, data_off)[0]
        comp_type = buf[data_off + 4]

        compressed_data = buf[data_off + 5:offset + sec_size]
        prefix = '  ' * depth

        if comp_type == EFI_NOT_COMPRESSED:
            # 未压缩，直接递归解析
            inner_start = align_up(data_off + 5, 4)
            inner_sections = self._parse_sections(buf, inner_start, offset + sec_size, depth + 1)
            sections.extend(inner_sections)

        elif comp_type == EFI_STANDARD_COMPRESSION:
            print(f'{prefix}  [LZMA COMPRESSION] compressed={len(compressed_data)} uncomp={uncomp_len}')
            decompressed = try_lzma_decompress(compressed_data)
            if decompressed:
                print(f'{prefix}  [DECOMPRESSED] {len(decompressed)} bytes')
                # 在解压数据中递归解析 sections
                inner_sections = self._parse_sections(decompressed, 0, len(decompressed), depth + 1)
                # 对于解压数据中的 section，需要用解压后的 buffer 提取
                for isec in inner_sections:
                    sections.append({**isec, '_buf': decompressed})

                # 也在解压数据中扫描 FV
                self._scan_and_parse(decompressed, 0, depth + 1)
            else:
                print(f'{prefix}  [LZMA DECOMPRESSION FAILED]')

    def _handle_guid_defined_section(self, buf, sec, sections, depth):
        """处理 GUID-defined section"""
        offset = sec['offset']
        sec_hdr = sec['hdr_size']
        sec_size = sec['size']

        if sec_hdr + 20 > sec_size:
            return

        data_off = offset + sec_hdr
        guid = read_guid(buf, data_off)
        data_offset_field = struct.unpack_from('<H', buf, data_off + 16)[0]
        attrs = struct.unpack_from('<H', buf, data_off + 18)[0]

        inner_start = offset + data_offset_field
        inner_data = buf[inner_start:offset + sec_size]

        prefix = '  ' * depth

        if guid == LZMA_COMPRESS_GUID:
            print(f'{prefix}  [GUID LZMA] {len(inner_data)} bytes compressed')
            decompressed = try_lzma_decompress(inner_data)
            if decompressed:
                print(f'{prefix}  [DECOMPRESSED] {len(decompressed)} bytes')
                inner_sections = self._parse_sections(decompressed, 0, len(decompressed), depth + 1)
                for isec in inner_sections:
                    sections.append({**isec, '_buf': decompressed})
                self._scan_and_parse(decompressed, 0, depth + 1)
            else:
                print(f'{prefix}  [GUID LZMA DECOMPRESSION FAILED]')
        else:
            # 尝试直接解析
            inner_start_aligned = align_up(inner_start, 4)
            inner_sections = self._parse_sections(buf, inner_start_aligned, offset + sec_size, depth + 1)
            sections.extend(inner_sections)

    def _get_ui_name(self, buf, sections):
        for sec in sections:
            if sec['type'] == EFI_SECTION_USER_INTERFACE:
                b = sec.get('_buf', buf)
                off = sec['offset'] + sec['hdr_size']
                size = sec['size'] - sec['hdr_size']
                try:
                    return b[off:off + size].decode('utf-16-le').rstrip('\x00')
                except (UnicodeDecodeError, ValueError):
                    pass
        return None

    def _get_pe32(self, buf, sections):
        for sec in sections:
            if sec['type'] in (EFI_SECTION_PE32, EFI_SECTION_TE):
                b = sec.get('_buf', buf)
                off = sec['offset'] + sec['hdr_size']
                size = sec['size'] - sec['hdr_size']
                return b[off:off + size]
        return None

def main():
    if len(sys.argv) < 2:
        print(f'用法: {sys.argv[0]} <abl.img> [output.efi]')
        sys.exit(1)

    abl_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'LinuxLoader.efi'

    if not os.path.isfile(abl_path):
        print(f'错误: 文件不存在 - {abl_path}')
        sys.exit(1)

    with open(abl_path, 'rb') as f:
        data = f.read()

    print(f'读取 {abl_path} ...')
    extractor = EfiExtractor(data)
    extractor.run()

    # 查找 LinuxLoader
    linuxloader = None
    all_apps = []

    for name, guid, pe_data in extractor.results:
        all_apps.append((name, guid, pe_data))
        if name and 'linuxloader' in name.lower():
            linuxloader = (name, guid, pe_data)

    if linuxloader:
        name, guid, pe_data = linuxloader
        with open(output_path, 'wb') as f:
            f.write(pe_data)
        print(f'\n成功: {output_path} ({len(pe_data)} bytes)')
        sys.exit(0)

    if all_apps:
        print(f'\n未找到 LinuxLoader，导出全部 {len(all_apps)} 个 EFI 文件:')
        for i, (name, guid, pe_data) in enumerate(all_apps):
            safe_name = (name or guid).replace('/', '_').replace('\\', '_')
            out = f'{safe_name}.efi'
            with open(out, 'wb') as f:
                f.write(pe_data)
            print(f'  {out} ({len(pe_data)} bytes)')
        sys.exit(1)

    print('\n提取失败')
    sys.exit(1)

if __name__ == '__main__':
    main()
