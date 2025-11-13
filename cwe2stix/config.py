import logging
import os

from uuid import UUID
from stix2 import FileSystemStore

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)

namespace = UUID("d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b")

file_system_path = "stix2_objects"
os.makedirs(file_system_path, exist_ok=True)
fs = FileSystemStore("stix2_objects")

raw_data_xml = "data/raw_xml/"
cwe2stix_version_filename = "CWE_VERSION"

## IMPORT STANDARD OBJECTS

DOGESEC_IDENTITY = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/dogesec.json"
CWE2STIX_MARKING_DEFINITION = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/cwe2stix.json"
WEAKNESS_EXTENSION_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/automodel_generated/extension-definitions/sdos/weakness.json"
TLP_CLEAR_MARKING_DEFINITION = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"