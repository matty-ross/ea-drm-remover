from tkinter import filedialog

from ea_drm import EA_DRM


def main() -> None:
    license_path = filedialog.askopenfilename(title="License file")
    pe_path = filedialog.askopenfilename(title="PE file")
    new_pe_path = filedialog.asksaveasfilename(title="New PE file", defaultextension='exe')
    
    ea_drm = EA_DRM(license_path, pe_path)
    ea_drm.fix_pe_header()
    ea_drm.decrypt_sections()
    ea_drm.save_pe(new_pe_path)


if __name__ == '__main__':
    main()
