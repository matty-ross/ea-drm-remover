import tomllib
from dataclasses import dataclass


@dataclass
class EaDrmConfig:
    encrypted_sections_offset: int
    original_data_directories_offset: int


def load(file_path: str) -> EaDrmConfig:
    with open(file_path, 'rb') as file:
        config = tomllib.load(file)

    return EaDrmConfig(**config)
