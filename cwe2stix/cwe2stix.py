"""Main module."""
import logging
import os
import shutil
import sys

from cwe2stix import mapper, utils
from cwe2stix.version_manager import VersionManager
from cwe2stix import config


class Cwe2Stix:
    def __init__(self, version=None):
        self.url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        if version:
            self.url = f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
        self.version = version

    def process_download(self):
        config.filename = utils.download_and_extract_zip(self.url, config.raw_data_xml)

    def version_check(self):
        version_manager = VersionManager()
        if os.path.exists(version_manager.version_manager):
            os.remove(version_manager.version_manager)
        filename = self.url.split("https://cwe.mitre.org/data/xml/")[1].replace(".zip", "")
        if not self.version:
            filename = utils.download_and_extract_zip(self.url, config.raw_data_xml)
        version = version_manager.extract_version_from_file(filename)
        already_processed_file = version_manager.is_file_update(filename)
        VersionManager().update_version_file(filename)
        logging.info(f"New Version: v{version} detected !")
        return version, already_processed_file

    def convert_xml_json(self):
        return utils.xml_to_json(config.raw_data_xml, config.filename)

    def run_parser(self):
        logging.info(f"Parsing start with xml file:{config.filename}")
        mapper.mapper(self.convert_xml_json())
        logging.info(f"Parsing completed: {config.filename}")

    def clean_filesystem(self):
        logging.info("Deleting old data from filesystem")
        for filename in os.listdir(config.file_system):
            file_path = os.path.join(config.file_system, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}. Reason: {e}")
        logging.info("Deletion done!")

    def clean_data_dir(self):
        data_json_dir = "data/raw_json/"
        data_xml_dir = "data/raw_xml/"
        if os.path.isdir(data_xml_dir):
            shutil.rmtree(data_xml_dir)
        if os.path.isdir(data_json_dir):
            shutil.rmtree(data_json_dir)
            shutil.rmtree("data/")
        logging.info(f"Delete data folder: {data_json_dir}, {data_xml_dir}")
        logging.info(os.listdir())

    def run(self):
        self.version_check()
        self.process_download()
        self.clean_filesystem()
        self.run_parser()
        self.clean_data_dir()
