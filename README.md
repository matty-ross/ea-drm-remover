# EA DRM Remover

![](https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=FFDD54)

A tool to remove EA DRM from PE files.


## Config file

This tool requires a config file in TOML format:

```toml
# Offsets are relative to the start of the .ooa section
# NOTE: This config is for Burnout Paradise Remastered

# Offset to the misc data containing the first original TLS callback and the original entry point
misc_offset = 0x3DA

# Offset to the encrypted sections data
encrypted_sections_offset = 0x3EE

# Offset to the original data directories
original_data_directories_offset = 0x5E4
```


## Usage

```
python .\src\main.py
```

1. Choose the game's PE file (`*.exe`)
1. Choose the game's license file (`*.dlf`)
1. Choose the config file (`*.toml`)
1. Choose where to save the new PE file
