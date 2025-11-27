import struct
import base64
from dataclasses import dataclass

import pefile
from Crypto.Cipher import AES
from Crypto.Util import Padding


LICENSE_KEY = base64.b64decode("QTJyLdCC77DcZFfFdmjKCQ==")

# TODO: move these offsets to a config file (or try to compute them?)
ENTRY_POINT_OFFSET = 0x3EA
DATA_DIRECTORIES_OFFSET = 0x5E4
ENCRYPTED_SECTIONS_TABLE_OFFSET = 0x3EE


@dataclass
class EncryptedSection:
    rva: int
    encrypted_size: int
    decrypted_size: int
    padding: bytes


class EA_DRM:

    def __init__(self, license_path: str, pe_path: str):
        self._decryption_key = self._get_decryption_key(license_path)
        self._pe = pefile.PE(pe_path, fast_load=True)
        self._ooa_rva = self._get_oaa_section_rva()


    def save_pe(self, new_pe_path: str) -> None:
        self._pe.OPTIONAL_HEADER.CheckSum = self._pe.generate_checksum()
        self._pe.write(new_pe_path)

    
    def decrypt_sections(self) -> None:
        count = self._read_ooa(ENCRYPTED_SECTIONS_TABLE_OFFSET, 'B')
        for i in range(count):
            offset = ENCRYPTED_SECTIONS_TABLE_OFFSET + 0x1 + i * 0x30
            encrypted_section = EncryptedSection(
                rva=self._read_ooa(offset + 0x0, '<L'),
                encrypted_size=self._read_ooa(offset + 0x4, '<L'),
                decrypted_size=self._read_ooa(offset + 0x8, '<L'),
                padding=self._read_ooa(offset + 0x20, '16B'),
            )
            self._decrypt_section(encrypted_section)


    def fix_pe_header(self) -> None:
        self._pe.OPTIONAL_HEADER.AddressOfEntryPoint = self._read_ooa(ENTRY_POINT_OFFSET, '<L')
        
        get_data_directory = lambda name: self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[name]]
        get_data_directory('IMAGE_DIRECTORY_ENTRY_IMPORT').VirtualAddress = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0x0, '<L')
        get_data_directory('IMAGE_DIRECTORY_ENTRY_IMPORT').Size = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0x4, '<L')
        get_data_directory('IMAGE_DIRECTORY_ENTRY_BASERELOC').VirtualAddress = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0x8, '<L')
        get_data_directory('IMAGE_DIRECTORY_ENTRY_BASERELOC').Size = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0xC, '<L')
        get_data_directory('IMAGE_DIRECTORY_ENTRY_IAT').VirtualAddress = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0x10, '<L')
        get_data_directory('IMAGE_DIRECTORY_ENTRY_IAT').Size = self._read_ooa(DATA_DIRECTORIES_OFFSET + 0x14, '<L')


    def _decrypt_section(self, encrypted_section: EncryptedSection) -> None:
        encrypted_data = self._pe.get_data(encrypted_section.rva, encrypted_section.encrypted_size)
        assert len(encrypted_data) == encrypted_section.encrypted_size
        
        decrypted_data = EA_DRM._aes_decrypt(self._decryption_key, encrypted_data)
        assert len(decrypted_data) == encrypted_section.decrypted_size
        
        padding = bytearray(16)
        for i in range(16):
            padding[i] = decrypted_data[encrypted_section.decrypted_size - 0x10 + i] ^ encrypted_section.padding[i]

        self._pe.set_bytes_at_rva(encrypted_section.rva, decrypted_data + padding)


    def _get_decryption_key(self, license_path: str) -> bytes:
        with open(license_path, 'rb') as license_file:
            license_file.seek(0x41)
            encrypted_license = license_file.read()
        
        decrypted_license = EA_DRM._aes_decrypt(LICENSE_KEY, encrypted_license).decode('utf-8')
        
        start = decrypted_license.find('<CipherKey>') + 11
        end = decrypted_license.find('</CipherKey>')
        return base64.b64decode(decrypted_license[start:end])[:16]
    

    def _get_oaa_section_rva(self) -> int:
        for section in self._pe.sections:
            if section.Name.rstrip(b'\x00') == b'.ooa':
                return section.VirtualAddress
        raise Exception(f"No .ooa section in the PE file.")

    
    def _read_ooa(self, offset: int, format: str):
        rva = self._ooa_rva + offset
        buffer = self._pe.get_data(rva, struct.calcsize(format))
        value = struct.unpack(format, buffer)
        return value[0] if len(value) == 1 else value
    

    @staticmethod
    def _aes_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
        aes = AES.new(key, AES.MODE_CBC, iv=bytes(16))
        decrypted_data = Padding.unpad(aes.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
