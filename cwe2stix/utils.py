import json
import logging
import os
import zipfile
from datetime import datetime

import hashlib
import requests
from . import config
import xmltodict
import xml.etree.ElementTree as ET


def download_and_extract_zip(url, directory):
    try:
        # Create the directory if it doesn't exist
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Extract the file name from the URL
        file_name = url.split("/")[-1]

        # Download the zip file
        response = requests.get(url)
        response.raise_for_status()  # Check for any download errors
        zip_path = os.path.join(directory, file_name)
        with open(zip_path, "wb") as file:
            file.write(response.content)

        # Extract the contents of the zip file
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(directory)

        # Remove the zip file
        os.remove(zip_path)

        logging.info("Zip file downloaded, extracted, and removed successfully!")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error occurred during the download: {e}")
    except zipfile.BadZipFile as e:
        logging.error(f"Error occurred while extracting the zip file: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    return os.listdir(directory)[0]


def xml_to_json(xml_folder, filename):
    xml_file = f"{xml_folder}{filename}"
    data_folder = "data/raw_json/"
    json_file = f"{data_folder}{filename}.json"
    with open(xml_file) as file:
        xml_data = file.read()

    json_data = xmltodict.parse(xml_data)
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
    with open(json_file, "w") as file:
        json.dump(json_data, file, indent=4)
    return json_data


def load_json_file(
    filename, data_folder="data/", include_filepath=False
):
    path = filename
    if not include_filepath:
        path = os.path.join(data_folder, filename)
    return json.load(open(path))


def write_json_file(folder, filename, data):
    logging.info(f"Creating folder or searching: {folder}")
    if not os.path.exists(folder):
        os.makedirs(folder)
    logging.info(f"Folder created or already exists: {folder}")
    json_file = os.path.join(folder, filename)
    with open(json_file, "w") as file:
        json.dump(data, file, indent=4)


def parse_datetime(date):
    if date:
        return datetime.strptime(date, "%Y-%m-%d")


def publish_datetime_format(datetime_str):
    return datetime.strptime(datetime_str, "%Y-%m-%d").strftime("%Y%m%d%H%M%S%f")[:-3]


def get_object_by_id(id):
    if not config.tree:
        tree = config.get_update_file_root()
    root = tree.getroot()
    for child in root[0]:
        if child.get("ID") == id:
            return child
    return None


def get_extended_description(id):
    description = ""
    for i in get_object_by_id(id)[1]:
        description += str(ET.tostring(i, encoding="unicode")).replace(
            ' xmlns:html="http://www.w3.org/1999/xhtml"', ""
        )
    return description


def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error loading JSON from {url}: {e}")
        return None


def generate_md5_from_list(stix_objects: list) -> str:
    json_str = json.dumps(stix_objects, sort_keys=True).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()

def serialized_json(stix_objects):
    temp_object_list = []
    for obj in iter(stix_objects):
        if not isinstance(obj, dict) and not isinstance(obj, str):
            temp_object_list.append(obj.serialize())
        else:
            temp_object_list.append(obj)
    return temp_object_list