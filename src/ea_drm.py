import struct
import base64
from xml.etree import ElementTree

import pefile
from Crypto.Cipher import AES
from Crypto.Util import Padding

from ea_drm_config import EaDrmConfig


_LICENSE_CIPHER_KEY = base64.b64decode("QTJyLdCC77DcZFfFdmjKCQ==")
_OOA_PE_SECTION_NAME = '.ooa'


def get_cipher_key(license_file_path: str) -> bytes:
    with open(license_file_path, 'rb') as license_file:
        license_file.seek(0x41)
        encrypted_license = license_file.read()

    decrypted_license = _aes_decrypt(encrypted_license, _LICENSE_CIPHER_KEY)

    xml = ElementTree.fromstring(decrypted_license.decode('utf-8'))
    cipher_key = xml.find('CipherKey')

    return base64.b64decode(cipher_key)[:16]


def decrypt_sections(pe: pefile.PE, config: EaDrmConfig, cipher_key: bytes) -> None:
    ooa_data = _get_ooa_data(pe)

    count = struct.unpack_from('B', ooa_data, config.encrypted_sections_offset + 0x0)[0]
    for i in range(count):
        offset = config.encrypted_sections_offset + 0x1 * i * 0x30

        rva = struct.unpack_from('<L', ooa_data, offset + 0x0)[0]
        encrypted_size = struct.unpack_from('<L', ooa_data, offset + 0x4)[0]
        decrypted_size = struct.unpack_from('<L', ooa_data, offset + 0x8)[0]
        padding = struct.unpack_from('16B', ooa_data, offset + 0x20)

        encrypted_data = pe.get_data(rva, encrypted_size)
        decrypted_data = _aes_decrypt(encrypted_data, cipher_key)
        pe.set_bytes_at_rva(rva, decrypted_data + bytes(decrypted_data[decrypted_size - 0x10 + i] ^ padding[i] for i in range(16)))


def fix_pe_header(pe: pefile.PE, config: EaDrmConfig) -> None:
    ooa_data = _get_ooa_data(pe)

    pe.OPTIONAL_HEADER.AddressOfEntryPoint = struct.unpack_from('<L', ooa_data, config.misc_offset + 0x10)

    data_directory_names = [
        'IMAGE_DIRECTORY_ENTRY_IMPORT',
        'IMAGE_DIRECTORY_ENTRY_BASERELOC',
        'IMAGE_DIRECTORY_ENTRY_IAT',
    ]
    for i, data_directory_name in enumerate(data_directory_names):
        data_directory = _get_pe_data_directory(pe, data_directory_name)
        data_directory.VirtualAddress = struct.unpack_from('<L', ooa_data, config.original_data_directories_offset + i * 0x8 + 0x0)[0]
        data_directory.Size = struct.unpack_from('<L', ooa_data, config.original_data_directories_offset + i * 0x8 + 0x4)[0]


def fix_tls_callback(pe: pefile.PE, config: EaDrmConfig) -> None:
    pass


def _get_ooa_data(pe: pefile.PE) -> bytes:
    for section in pe.sections:
        section_name = _decode_pe_section_name(section.Name)
        if section_name == _OOA_PE_SECTION_NAME:
            return section.get_data()
    raise Exception(f"No {_OOA_PE_SECTION_NAME} section in the PE file.")


def _aes_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv=bytes(16))
    decrypted_data = Padding.unpad(aes.decrypt(encrypted_data), AES.block_size)
    return decrypted_data


def _get_pe_data_directory(pe: pefile.PE, data_directory_name: str) -> pefile.Structure:
    data_directory_index = pefile.DIRECTORY_ENTRY[data_directory_name]
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[data_directory_index]


def _decode_pe_section_name(section_name: bytes) -> str:
    return section_name.rstrip(b'\x00').decode('ascii')
