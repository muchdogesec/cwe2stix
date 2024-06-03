import logging
import os

from uuid import UUID
from stix2 import FileSystemStore
import xml.etree.ElementTree as ET

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)

namespace = UUID("d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b")

file_system = "stix2_objects"
if not os.path.exists(file_system):
    os.makedirs(file_system)
fs = FileSystemStore("stix2_objects")

raw_data_xml = "data/raw_xml/"
raw_data_json = "data/raw_json/"
cwe2stix_version_filename = "CWE_VERSION"
filename = "cwec_v4.13.xml"
root = None
tree = None
cwe2stix_version = ""

## IMPORT STANDARD OBJECTS

CWE2STIX_IDENTITY = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/cwe2stix.json"
CWE2STIX_MARKING_DEFINITION = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/cwe2stix.json"
WEAKNESS_EXTENSION_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/extension-definition/weakness.json"
TLP_CLEAR_MARKING_DEFINITION = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"

# try:
#     with open(cwe2stix_version_filename, 'r') as file:
#         cwe2stix_version = file.read()
# except FileNotFoundError:
#     logging.error(f"File not found: '{cwe2stix_version_filename}'")
# except IOError:
#     logging.error(f"Error reading file: '{cwe2stix_version_filename}'")
#

def read_file(filename):
    try:
        with open(filename) as file:
            content = file.read()
    except FileNotFoundError:
        logging.error(f"File not found: '{filename}'")
    except OSError:
        logging.error(f"Error reading file: '{filename}'")

    # return content


def get_update_file_root():
    if filename and os.path.exists(raw_data_xml):
        tree = ET.parse(raw_data_xml + filename)
    return tree


cwe2stix_version = read_file(cwe2stix_version_filename)
