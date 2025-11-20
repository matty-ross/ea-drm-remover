from tkinter import filedialog

from ea_drm import EA_DRM


def main() -> None:
    pe_path = filedialog.askopenfilename()
    ea_drm = EA_DRM(pe_path)
    ea_drm.decrypt_sections()


if __name__ == '__main__':
    main()
