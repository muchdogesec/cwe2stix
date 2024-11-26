import json
import uuid
import logging

from stix2 import Bundle, ExternalReference, Filter, Relationship, parse, Grouping
# from cwe2stix.schema import Weakness
from stix2extensions.weakness import Weakness
from cwe2stix import utils
from typing import List  # noqa F401
from cwe2stix.config import namespace, fs, CWE2STIX_MARKING_DEFINITION, CWE2STIX_IDENTITY, WEAKNESS_EXTENSION_DEFINITION_URL, TLP_CLEAR_MARKING_DEFINITION
from tqdm import tqdm

external_reference_author_objects = {}
object_list = []
version = ""

identity_ref = json.loads(utils.load_file_from_url(CWE2STIX_IDENTITY))
marking_definition_refs = json.loads(utils.load_file_from_url(CWE2STIX_MARKING_DEFINITION))
extension_definition = json.loads(utils.load_file_from_url(WEAKNESS_EXTENSION_DEFINITION_URL))


def map_extension_definition():
    logging.info("Extension Definition creation start")
    extension_definition = parse(json.loads(utils.load_file_from_url(WEAKNESS_EXTENSION_DEFINITION_URL)))
    object_list.append(extension_definition.serialize())
    fs.add(extension_definition)
    logging.info("Extension Definition added in file system")

def map_identity():
    identity = parse(identity_ref)
    object_list.append(identity.serialize())
    fs.add(identity)

def map_marketing_definition():
    global marking_definition_refs
    marking_definition_refs = parse(marking_definition_refs)
    object_list.append(marking_definition_refs.serialize())
    fs.add(marking_definition_refs)


def map_bundle(data):
    logging.info("Bundle creation start")
    global object_list
    timestamp_filename = utils.publish_datetime_format(data.get("@Date"))
    logging.info(f"Bundle filename: {timestamp_filename}")
    object_list = utils.serialized_json(object_list)
    id = "bundle--" + str(uuid.uuid5(namespace, f"bundle+{utils.generate_md5_from_list(object_list)}"))
    logging.info(f"Bundle generated Id: {id}")
    bundle = Bundle(id=id, objects=object_list, allow_custom=True)
    logging.info(
        f"Saving bundle in file now : stix2_objects/bundle/{id}/{timestamp_filename}.json"
    )
    # utils.write_json_file(
    #     f"stix2_objects/bundle/{id}/",
    #     f"{timestamp_filename}.json",
    #     json.loads(bundle.serialize()),
    # )
    utils.write_json_file(
        f"stix2_objects/",
        f"cwe-bundle.json",
        json.loads(bundle.serialize()),
    )
    logging.info(
        f"Bundle file save in : stix2_objects/bundle/{id}/{timestamp_filename}.json"
    )


def load_external_references(data: dict):
    logging.info("Loading external references started")
    external_references_list = data.get("External_References").get("External_Reference")
    logging.info(f"Total external references: {len(external_references_list)} to load")
    for external_reference in external_references_list:
        author_name = external_reference.get("Title")
        if external_reference.get("Author", None):
            author_name = (
                ", ".join(external_reference.get("Author"))
                if isinstance(external_reference.get("Author"), list)
                else external_reference.get("Author")
            )

        external_reference_author_objects[
            external_reference.get("@Reference_ID")
        ] = ExternalReference(
            source_name=author_name,
            description=external_reference.get("Title"),
            url=external_reference.get("URL"),
            external_id=external_reference.get("@Reference_ID"),
        )
        logging.info(
            f"Total external references loaded: {len(external_reference_author_objects)}"
        )


def map_external_author_reference(external_ref_ids) -> List[ExternalReference]:
    if isinstance(external_ref_ids, dict):
        external_ref_ids = [external_ref_ids]
    return [
        external_reference_author_objects.get(id.get("@External_Reference_ID"))
        for id in external_ref_ids
    ]


def map_external_references(data: dict) -> list:
    external_references = list()
    external_references.append(
        ExternalReference(
            source_name="cwe",
            external_id=f"CWE-{data.get('@ID')}",
            url=f"http://cwe.mitre.org/data/definitions/{data.get('@ID')}.html",
        )
    )
    external_references.extend(
        map_external_author_reference(data.get("References", {}).get("Reference", []))
    )
    if data.get("Taxonomy_Mappings", None):
        taxonomys = data.get("Taxonomy_Mappings").get("Taxonomy_Mapping")
        if isinstance(taxonomys, dict):
            taxonomys = [taxonomys]
        for taxonomy in taxonomys:
            external_references.append(
                ExternalReference(
                    source_name=taxonomy.get("@Taxonomy_Name"),
                    external_id=taxonomy.get("Entry_ID"),
                    description=taxonomy.get("Entry_Name"),
                )
            )

    if data.get("Related_Attack_Patterns", None):
        attacks = data.get("Related_Attack_Patterns").get("Related_Attack_Pattern")
        if isinstance(attacks, dict):
            attacks = [attacks]
        for attack in attacks:
            external_references.append(
                ExternalReference(
                    source_name="capec",
                    external_id=f"CAPEC-{attack.get('@CAPEC_ID')}",
                    url=f"https://capec.mitre.org/data/definitions/{attack.get('@CAPEC_ID')}.html",
                )
            )
    return external_references


def parse_date(weakness):
    modified_date = weakness.get("Content_History").get("Modification")
    if isinstance(modified_date, dict):
        modified_date = [modified_date]
    if not modified_date:
        modified_date = (
            weakness.get("Content_History").get("Submission").get("Submission_Date")
        )
    else:
        modified_date = modified_date[-1].get("Modification_Date")

    submission_date = (
        weakness.get("Content_History", {})
        .get("Submission", {})
        .get("Submission_Date", None)
    )
    if not submission_date:
        submission_date = modified_date

    return utils.parse_datetime(modified_date), utils.parse_datetime(submission_date)


def parse_common_consequences(weakness):
    consequences = elem_as_list(weakness.get("Common_Consequences", {}).get('Consequence'))
    scope = [c['Scope'] for c in consequences]
    retval = []
    for s in scope:
        retval.extend(elem_as_list(s))
    return retval

def elem_as_list(elem):
    if isinstance(elem, list):
        return elem
    if elem is None:
        return []
    return [elem]

def parse_detection_methods(weakness):
    methods = elem_as_list(weakness.get("Detection_Methods", {}).get('Detection_Method'))
    return [dm["Method"] for dm in methods]

def parse_phase_properties(weakness: dict):
    common_consequences = parse_common_consequences(weakness)
    modes_of_introduction = elem_as_list(weakness.get("Modes_Of_Introduction", {}).get("Introduction", []))
    modes_of_introduction = [intro["Phase"] for intro in modes_of_introduction if intro.get("Phase")]
    likelihood_of_exploit = weakness.get("Likelihood_Of_Exploit", None)

    return common_consequences, likelihood_of_exploit, modes_of_introduction


def parse_vulnerability(weakness: dict):

    generated_uuid = uuid.uuid5(namespace, f"CWE-{weakness.get('@ID')}")
    logging.info(f"Weakness: {weakness.get('@ID')}, {generated_uuid}")
    external_references = map_external_references(weakness)
    extended_description = weakness.get("Extended_Description")
    if isinstance(extended_description, dict):
        extended_description = utils.get_extended_description(weakness.get("@ID"))

    modified_date, submission_date = parse_date(weakness)
    print(marking_definition_refs.get("id"))
    common_consequences, likelihood_of_exploit, modes_of_introduction = parse_phase_properties(weakness)
    weakness_name: str = weakness.get("@Name")
    description = weakness.get('Description')
    if extended_description:
        description += "\n" + extended_description

    weakness_ = Weakness(
        id="weakness--" + str(generated_uuid),
        name=weakness_name,
        description=description,
        created=submission_date,
        modified=modified_date,
        external_references=external_references,
        object_marking_refs=[TLP_CLEAR_MARKING_DEFINITION]+[marking_definition_refs.get("id")],
        created_by_ref=identity_ref.get("id"),
        extensions={
            "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
                "extension_type": "new-sdo"
            }
        },
        revoked=weakness_name.startswith('DEPRECATED:'),
        # custom_properties={"x_cwe_version": version},
        common_consequences=common_consequences,
        likelihood_of_exploit=likelihood_of_exploit,
        modes_of_introduction=modes_of_introduction,
        detection_methods=parse_detection_methods(weakness),
    )
    object_list.append(weakness_)
    fs.add(weakness_)


def map_vulnerabilities(data: dict) -> None:
    weaknesses = data.get("Weaknesses", []).get("Weakness", None)
    logging.info(f"Processing vulnerabilities now: {len(weaknesses)}")
    for i, weakness in enumerate(tqdm(weaknesses)):
        parse_vulnerability(weakness)
    logging.info(f"Total Weaknesses created: {len(weaknesses)}")


def get_related_object(id, object_type):

    generated_id = "{}--{}".format(object_type, str(uuid.uuid5(namespace, f"CWE-{id}")))
    return fs.query([Filter("id", "=", generated_id)])[0]


def parse_relations(relations: dict, weakness) -> None:
    for i, relation in enumerate(relations):
        logging.info(f"Relation creating: {relation}")
        generated_id = "relationship--" + str(
            uuid.uuid5(
                namespace,
                "{}+{}+{}".format(
                    relation.get("@Nature"),
                    get_related_object(weakness.get("@ID"), "weakness").id,
                    get_related_object(relation.get("@CWE_ID"), "weakness").id,
                ),
            )
        )
        results = fs.query([Filter("id", "=", generated_id)])
        modified_date, submission_date = parse_date(weakness)
        if len(results) == 0:
            source = get_related_object(weakness.get("@ID"), "weakness")
            target = get_related_object(relation.get("@CWE_ID"), "weakness")
            nature = relation.get("@Nature")
            rel = Relationship(
                id=generated_id,
                created=submission_date,
                modified=modified_date,
                description=f"{source.name} is a {nature} of {target.name}",
                relationship_type=nature,
                source_ref=source.id,
                target_ref=target.id,
                created_by_ref=identity_ref.get("id"),
                object_marking_refs=[TLP_CLEAR_MARKING_DEFINITION]+[marking_definition_refs.get("id")],
            )
            object_list.append(rel)
            fs.add(rel)


def map_relationship(data: dict):
    weaknesses = data.get("Weaknesses", []).get("Weakness", None)
    logging.info("Processing relations now ")
    for i, weakness in enumerate(tqdm(weaknesses)):
        if weakness.get("Related_Weaknesses", None):
            related_weaknesses = weakness.get("Related_Weaknesses").get(
                "Related_Weakness"
            )
            if isinstance(related_weaknesses, dict):
                related_weaknesses = [related_weaknesses]
            parse_relations(related_weaknesses, weakness)
    logging.info(
        f"Total relations created: {len(fs.query([Filter('type', '=', 'relationship')] ))}"
    )


def parse_category(category: dict):
    generated_uuid = uuid.uuid5(namespace, category.get("@Name"))
    logging.info(f"grouping: {category.get('@ID')}, {generated_uuid}")
    modified_date, submission_date = parse_date(category)
    object_refs_list = []
    categories = category.get("Relationships", {}).get("Has_Member", [])
    if isinstance(categories, dict):
        categories = [categories]
    for cat in categories:
        logging.info(f"Processing related object: {cat.get('@CWE_ID')}")
        try:
            related_object = get_related_object(cat.get("@CWE_ID"), "weakness")
            if related_object:
                object_refs_list.append(related_object.id)
        except Exception as e:
            logging.error(f"Processing related object: {cat.get('@CWE_ID')}")

    external_ref = [
        ExternalReference(source_name="cwe_category", external_id=category.get("@ID")),
    ]
    external_ref.extend(
        map_external_author_reference(
            category.get("References", {}).get("Reference", [])
        )
    )
    if len(object_refs_list) > 0:
        group = Grouping(
            id=f"grouping--{str(generated_uuid)}",
            name="{}".format(category.get("@Name")),
            description=f"{category.get('Summary')}",
            created=submission_date,
            modified=modified_date,
            context="unspecified",
            external_references=external_ref,
            created_by_ref=identity_ref.get("id"),
            object_marking_refs=[TLP_CLEAR_MARKING_DEFINITION]+[marking_definition_refs.get("id")],
            object_refs=object_refs_list,
        )
        object_list.append(group)
        fs.add(group)


def map_categories(data: dict):
    categories = data.get("Categories", []).get("Category", None)
    logging.info(f"Processing categories now: {len(categories)}")
    for i, category in enumerate(tqdm(categories)):
        if category.get("@Status") != "Deprecated" and category.get(
            "Relationships", None
        ):
            parse_category(category)
    logging.info(f"Total Weaknesses created: {len(categories)}")


def mapper(data):
    global version
    data = data.get("Weakness_Catalog")
    version = data.get("@Version")
    load_external_references(data)
    map_vulnerabilities(data)
    map_extension_definition()
    map_identity()
    map_marketing_definition()
    map_relationship(data)
    map_categories(data)
    #parse_default_objects()
    map_bundle(data)
