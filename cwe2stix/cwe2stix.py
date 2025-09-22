"""Main module."""

import io
import json
import logging
import os
from pathlib import Path
import shutil
import uuid
import zipfile

from xml.dom.minidom import Element, parse
import requests
from stix2 import ExternalReference, Grouping
from cwe2stix import utils
from cwe2stix import config
from stix2 import FileSystemStore, Relationship
from stix2extensions import Weakness
from . import xml_utils


class Cwe2Stix:
    def __init__(self, version=None, write_files=False):
        self.url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        if version:
            self.url = f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip"
        self.version = version
        self.writes_files = write_files
        self.fs = FileSystemStore("stix2_objects")
        if self.writes_files:
            self.clean_filesystem()

        self.external_reference_map: dict[str, dict] = {}
        self.all_objects = {}
        ###
        self.identity_obj = json.loads(
            utils.load_file_from_url(config.DOGESEC_IDENTITY)
        )
        self.add_object(self.identity_obj)
        self.marking_definition_obj = json.loads(
            utils.load_file_from_url(config.CWE2STIX_MARKING_DEFINITION)
        )
        self.add_object(self.marking_definition_obj)
        self.extension_definition = json.loads(
            utils.load_file_from_url(config.WEAKNESS_EXTENSION_DEFINITION_URL)
        )
        self.add_object(self.extension_definition)
        self.object_marking_refs = [
            config.TLP_CLEAR_MARKING_DEFINITION,
            self.marking_definition_obj["id"],
        ]

    def add_object(self, obj):
        if obj['id'] in self.all_objects:
            return
        self.all_objects[obj['id']] = obj

        if self.writes_files:
            self.fs.add(obj)

    def process_download(self):
        # self.xml_bytes = Path("/tmp/xmlbytes").read_bytes()
        # return
        response = requests.get(self.url)
        response.raise_for_status()  # Check for any download errors
        data_path = Path(config.raw_data_xml)

        # Extract the contents of the zip file
        with zipfile.ZipFile(io.BytesIO(response.content), "r") as zip_ref:
            zip_ref.extractall(config.raw_data_xml)
            for f in zip_ref.filelist:
                if f.is_dir():
                    continue
                self.xml_bytes = zip_ref.read(f)
                if self.writes_files:
                    data_path.mkdir(parents=True, exist_ok=True)
                    file_name = data_path / f.filename
                    file_name.write_bytes(self.xml_bytes)

    def parse(self):
        self.doc = parse(io.BytesIO(self.xml_bytes))
        self.catalog = self.doc.firstChild
        self.version = self.catalog.getAttribute("Version")
        self.external_reference_map = self.parse_external_references(self.catalog)
        self.map_weaknesses()
        self.map_categories()

    def parse_external_references(self, catalog: Element):
        external_reference_map = {}
        external_references_elem = xml_utils.firstOrNone(
            catalog.getElementsByTagName("External_References")
        )
        if not external_references_elem:
            return
        for c in external_references_elem.getElementsByTagName("External_Reference"):
            authors = []
            for author in c.getElementsByTagName("Author"):
                authors.append(xml_utils.getTextFromNode(author))
            ref_id = c.getAttribute("Reference_ID")
            external_reference_map[ref_id] = ExternalReference(
                source_name=", ".join(authors),
                description=xml_utils.getTextFromNode(
                    xml_utils.firstOrNone(c.getElementsByTagName("Title"))
                ),
                url=xml_utils.getTextFromNode(
                    xml_utils.firstOrNone(c.getElementsByTagName("URL"))
                ) or None,
                external_id=ref_id,
            )
        return external_reference_map

    def map_weaknesses(self):
        self.weakness_by_id = {}

        for weakness_el in self.catalog.getElementsByTagName("Weakness"):
            weakness = self.parse_weakness(weakness_el)
            self.add_object(weakness)
            self.weakness_by_id[weakness["external_references"][0]["external_id"]] = (
                weakness
            )

        for related_el in self.catalog.getElementsByTagName("Related_Weakness"):
            weakness_el = related_el.parentNode.parentNode
            weakness_id = "CWE-" + weakness_el.getAttribute("ID")
            related_id = "CWE-" + related_el.getAttribute("CWE_ID")
            source = self.weakness_by_id[weakness_id]
            target = self.weakness_by_id[related_id]
            nature = related_el.getAttribute("Nature")

            generated_id = "relationship--" + str(
                uuid.uuid5(
                    config.namespace,
                    "{}+{}+{}".format(
                        nature,
                        source.id,
                        target.id,
                    ),
                )
            )

            relationship = Relationship(
                id=generated_id,
                created=source.created,
                modified=source.modified,
                description=f"{source.name} is a {nature} of {target.name}",
                relationship_type=nature,
                source_ref=source.id,
                target_ref=target.id,
                created_by_ref=source.created_by_ref,
                object_marking_refs=source.object_marking_refs,
                external_references=[
                    source.external_references[0],
                    target.external_references[0],
                ],
            )
            self.add_object(relationship)

    def map_categories(self):
        categories_el = xml_utils.firstOrNone(
            self.catalog.getElementsByTagName("Categories")
        )
        if not categories_el:
            return
        for el in categories_el.getElementsByTagName("Category"):
            if el.getAttribute("Status") == "Deprecated":
                continue
            group = self.parse_category(el)
            if group:
                self.add_object(group)

    def parse_category(self, category_el: Element):
        object_refs = []
        group_id = category_el.getAttribute("ID")
        group_name = category_el.getAttribute("Name")
        generated_uuid = uuid.uuid5(config.namespace, group_name)
        modified, created = xml_utils.parse_dates(category_el)
        for el in category_el.getElementsByTagName("Has_Member"):
            cwe_id = "CWE-" + el.getAttribute("CWE_ID")
            try:
                member = self.weakness_by_id[cwe_id]
                object_refs.append(member.id)
            except KeyError as e:
                logging.error(f"Missing weakness referenced in group {group_id}")
        if not object_refs:
            return
        group = Grouping(
            id=f"grouping--{str(generated_uuid)}",
            name=group_name,
            description=xml_utils.getTextFromNode(
                xml_utils.firstOrNone(category_el.getElementsByTagName("Summary"))
            ),
            created=created,
            modified=modified,
            context="unspecified",
            external_references=[
                ExternalReference(
                    source_name="cwe_category",
                    external_id=group_id,
                ),
                *[
                    self.external_reference_map.get(
                        ref.getAttribute("External_Reference_ID")
                    )
                    for ref in category_el.getElementsByTagName("Reference")
                ],
            ],
            created_by_ref=self.identity_obj["id"],
            object_marking_refs=self.object_marking_refs,
            object_refs=object_refs,
        )
        return group

    def parse_weakness(self, weakness_el: Element):
        weakness_id = weakness_el.getAttribute("ID")
        cwe_id = f"CWE-" + weakness_id
        generated_uuid = uuid.uuid5(config.namespace, cwe_id)
        external_references = map_external_references(
            weakness_id, weakness_el, self.external_reference_map
        )
        modified, created = xml_utils.parse_dates(weakness_el)
        likelihood_of_exploit = (
            xml_utils.getTextFromNode(
                xml_utils.firstOrNone(
                    weakness_el.getElementsByTagName("Likelihood_Of_Exploit")
                )
            )
            or None
        )
        weakness_name = weakness_el.getAttribute("Name")
        weakness_ = Weakness(
            id="weakness--" + str(generated_uuid),
            name=weakness_name,
            description=xml_utils.parse_description(weakness_el),
            created=created,
            modified=modified,
            external_references=external_references,
            object_marking_refs=self.object_marking_refs,
            created_by_ref=self.identity_obj["id"],
            extensions={
                "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
                    "extension_type": "new-sdo"
                }
            },
            revoked=weakness_name.startswith("DEPRECATED:"),
            common_consequences=xml_utils.parse_common_consequences(weakness_el),
            likelihood_of_exploit=likelihood_of_exploit,
            modes_of_introduction=xml_utils.parse_modes_of_introduction(weakness_el),
            detection_methods=xml_utils.parse_detection_methods(weakness_el),
        )

        return weakness_

    def clean_filesystem(self):
        logging.info("Deleting old data from filesystem")
        for filename in os.listdir(config.file_system_path):
            file_path = os.path.join(config.file_system_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logging.error(f"Failed to delete {file_path}. Reason: {e}")
        logging.info("Deletion done!")

    def run_and_write(self):
        self.process_download()
        self.parse()
        utils.map_bundle(list(self.all_objects.values()))
        Path(config.cwe2stix_version_filename).write_text(self.version)


def map_external_references(weakness_id, weakness_el: Element, reference_map):
    refs = [
        ExternalReference(
            source_name="cwe",
            external_id=f"CWE-{weakness_id}",
            url=f"http://cwe.mitre.org/data/definitions/{weakness_id}.html",
        )
    ]
    if references_el := xml_utils.firstOrNone(
        weakness_el.getElementsByTagName("References")
    ):
        refs.extend(
            reference_map.get(ref.getAttribute("External_Reference_ID"))
            for ref in references_el.getElementsByTagName("Reference")
        )

    for taxonomy_mapping_el in weakness_el.getElementsByTagName("Taxonomy_Mapping"):
        refs.append(
            ExternalReference(
                source_name=taxonomy_mapping_el.getAttribute("Taxonomy_Name"),
                external_id=xml_utils.getTextFromNode(
                    xml_utils.firstOrNone(
                        taxonomy_mapping_el.getElementsByTagName("Entry_ID")
                    )
                ),
                description=xml_utils.getTextFromNode(
                    xml_utils.firstOrNone(
                        taxonomy_mapping_el.getElementsByTagName("Entry_Name")
                    )
                ),
            )
        )

    for related_capec_el in weakness_el.getElementsByTagName("Related_Attack_Pattern"):
        capec_id = related_capec_el.getAttribute("CAPEC_ID")
        refs.append(
            ExternalReference(
                source_name="capec",
                external_id="CAPEC-" + capec_id,
                url=f"https://capec.mitre.org/data/definitions/{capec_id}.html",
            )
        )

    return refs
