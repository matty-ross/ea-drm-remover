from tkinter import filedialog

from ea_drm import EA_DRM


def main() -> None:
    license_path = filedialog.askopenfilename()
    pe_path = filedialog.askopenfilename()
    
    ea_drm = EA_DRM(license_path, pe_path)
    ea_drm.fix_pe_header()
    ea_drm.decrypt_sections()
    ea_drm.save()


if __name__ == '__main__':
    main()
