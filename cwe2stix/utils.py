from functools import lru_cache
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import hashlib
import requests
from . import config
from stix2 import Bundle


def map_bundle(object_list):
    logging.info("Bundle creation start")
    object_list = serialized_json(object_list)
    id = "bundle--" + str(
        uuid.uuid5(config.namespace, f"bundle+{generate_md5_from_list(object_list)}")
    )
    logging.info(f"Bundle generated Id: {id}")
    bundle = Bundle(id=id, objects=object_list, allow_custom=True)
    write_json_file(
        f"stix2_objects/",
        f"cwe-bundle.json",
        json.loads(bundle.serialize()),
    )


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
        return datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=UTC)


@lru_cache
def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        raise


def generate_md5_from_list(stix_objects: list) -> str:
    json_str = json.dumps(stix_objects, sort_keys=True).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()


def serialized_json(stix_objects):
    temp_object_list = []
    for obj in iter(stix_objects):
        if not isinstance(obj, dict) and not isinstance(obj, str):
            temp_object_list.append(obj.serialize())
        else:
            temp_object_list.append(obj)
    return temp_object_list
