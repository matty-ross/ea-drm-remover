from tkinter import filedialog

import pefile

import ea_drm_config
import ea_drm


def main() -> None:
    pe_file_path = filedialog.askopenfilename(title="PE file")
    pe = pefile.PE(pe_file_path, fast_load=True)

    license_file_path = filedialog.askopenfilename(title="License file")
    cipher_key = ea_drm.get_cipher_key(license_file_path)

    config_file_path = filedialog.askopenfilename(title="EA DRM config file")
    config = ea_drm_config.load(config_file_path)

    print("Processing...")
    ea_drm.decrypt_sections(pe, config, cipher_key)
    ea_drm.fix_pe_header(pe, config)
    ea_drm.fix_tls_callback(pe, config)

    new_pe_file_path = filedialog.asksaveasfilename(title="New PE file", defaultextension='exe')
    print("Saving...")
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(new_pe_file_path)

    print("Done")


if __name__ == '__main__':
    main()
