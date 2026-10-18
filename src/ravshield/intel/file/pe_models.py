
from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PEHeader:
    machine: int
    number_of_sections: int
    timestamp: int
    size_of_optional_header: int
    characteristics: int


@dataclass(slots=True)
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_data_size: int
    raw_data_pointer: int
    characteristics: int


@dataclass(slots=True)
class PEDataDirectory:
    rva: int
    size: int


@dataclass(frozen=True)
class PEImportDescriptor:
    original_first_thunk: int
    time_date_stamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int
