import json
import pytest
from unittest.mock import call, patch, MagicMock
from cwe2stix.cwe2stix import Cwe2Stix, map_external_references
from cwe2stix import config
from stix2extensions import Weakness


import pytest
from unittest.mock import MagicMock
from xml.dom.minidom import parseString


@pytest.fixture
def fake_json_obj():
    return {"id": "identity--1234", "type": "identity", "name": "Fake Identity"}


@pytest.fixture
def fake_marking_obj():
    return {
        "id": "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
        "type": "marking-definition",
        "name": "dummy object",
    }


@pytest.fixture
def fake_extension_obj():
    return {
        "id": "extension--91011",
        "type": "extension-definition",
        "name": "Weakness",
    }


def test_cwe2stix_initialization_loads_objects(
    fake_json_obj, fake_marking_obj, fake_extension_obj
):
    # Arrange
    with patch("cwe2stix.utils.load_file_from_url") as mock_load:
        mock_load.side_effect = [
            json.dumps(fake_json_obj),
            json.dumps(fake_marking_obj),
            json.dumps(fake_extension_obj),
        ]

        # Act
        cwe2stix_obj = Cwe2Stix()
        assert (
            mock_load.call_count == 3
        ), "load_file_from_url must be called thrice for identity_ref, marking ref and extension def"

        # Assert
        assert fake_json_obj["id"] in cwe2stix_obj.all_objects
        assert fake_marking_obj["id"] in cwe2stix_obj.all_objects
        assert fake_extension_obj["id"] in cwe2stix_obj.all_objects
        # Should store marking refs properly
        assert fake_marking_obj["id"] in cwe2stix_obj.object_marking_refs
        assert cwe2stix_obj.object_marking_refs == [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
        ]


def test_add_object(cwe2stix_object):
    cwe2stix_object.writes_files = True
    with patch("cwe2stix.cwe2stix.FileSystemStore.add") as mock_fs_add:
        obj1 = {"id": "duplicated-object--1", "name": "first entry"}
        obj2 = {"id": "duplicated-object--1", "name": "second entry"}
        cwe2stix_object.add_object(obj1)
        assert "duplicated-object--1" in cwe2stix_object.all_objects
        mock_fs_add.assert_called_once_with(obj1)
        mock_fs_add.reset_mock()
        cwe2stix_object.add_object(obj2)
        assert "duplicated-object--1" in cwe2stix_object.all_objects
        mock_fs_add.assert_not_called()


def test_parse_sets_catalog_and_calls_helpers(cwe2stix_object):
    cwe = cwe2stix_object

    # Prepare minimal XML with Version attribute
    xml_content = """<?xml version="1.0"?>
    <Weakness_Catalog Version="4.7">
        <External_References/>
        <Weaknesses/>
        <Categories/>
    </Weakness_Catalog>
    """
    cwe.xml_bytes = xml_content.encode()

    # Patch the helper methods
    cwe.parse_external_references = MagicMock()
    cwe.map_weaknesses = MagicMock()
    cwe.map_categories = MagicMock()

    # Act
    cwe.parse()

    # Assert: sets catalog and version
    assert cwe.catalog.nodeName == "Weakness_Catalog"
    assert cwe.version == "4.7"

    # Assert: calls helper methods
    cwe.parse_external_references.assert_called_once_with(cwe.catalog)
    cwe.map_weaknesses.assert_called_once()
    cwe.map_categories.assert_called_once()


def test_map_weaknesses_adds_objects_and_relationships(cwe2stix_object):
    cwe = cwe2stix_object

    # Build fake XML with 2 Weaknesses and 1 Related_Weakness
    xml_content = """
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="100" Name="Buffer Overflow">
                <External_References/>
                <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
                <Relationships>
                    <Related_Weakness CWE_ID="200" Nature="ChildOf">
                    <Notes>Example relation</Notes>
                    </Related_Weakness>
                </Relationships>
            </Weakness>
            <Weakness ID="200" Name="SQL Injection">
                <External_References/>
                <Likelihood_Of_Exploit>Medium</Likelihood_Of_Exploit>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>
    """
    cwe.catalog = parseString(xml_content).documentElement

    # Map the fake weaknesses by ID to ensure Related_Weakness can resolve
    cwe.parse_weakness = MagicMock(
        side_effect=lambda el: Weakness(
            **{
                "name": el.getAttribute("Name"),
                "created": "2025-01-01T00:00:00Z",
                "modified": "2025-01-01T00:00:00Z",
                "external_references": [
                    {
                        "external_id": f"CWE-{el.getAttribute('ID')}",
                        "source_name": "cwe",
                    }
                ],
                "created_by_ref": cwe.identity_obj["id"],
                "object_marking_refs": cwe.object_marking_refs,
            }
        )
    )

    cwe.add_object = MagicMock()
    print(cwe.map_weaknesses)

    # Act
    cwe.map_weaknesses()

    # Assert weaknesses added
    assert "CWE-100" in cwe.weakness_by_id
    assert "CWE-200" in cwe.weakness_by_id
    assert cwe.weakness_by_id["CWE-100"]["name"] == "Buffer Overflow"
    assert cwe.weakness_by_id["CWE-200"]["name"] == "SQL Injection"
    cwe100_id = cwe.weakness_by_id["CWE-100"].id
    cwe200_id = cwe.weakness_by_id["CWE-200"].id

    # Should add both Weakness objects
    cwe.add_object.assert_has_calls(
        [call(obj) for obj in cwe.weakness_by_id.values()], any_order=True
    )

    # Should also add the generated Relationship
    relationships = [
        call[0][0]
        for call in cwe.add_object.call_args_list
        if call[0][0]["type"] == "relationship"
    ]
    assert relationships, "relationships must've been added"
    relationship_obj = relationships[0]
    assert relationship_obj.source_ref == cwe100_id
    assert relationship_obj.target_ref == cwe200_id
    assert relationship_obj.external_references == [
        {"external_id": "CWE-100", "source_name": "cwe"},
        {"external_id": "CWE-200", "source_name": "cwe"},
    ]


def test_map_categories_adds_groupings(cwe2stix_object):
    cwe = cwe2stix_object

    # Fake XML with Categories (1 valid, 1 deprecated)
    xml_content = """
    <Weakness_Catalog>
        <Categories>
            <Category ID="1000" Name="Input Validation Errors">
                <Has_Member CWE_ID="100"/>
            </Category>
            <Category ID="2000" Name="Deprecated Example" Status="Deprecated">
                <Has_Member CWE_ID="200"/>
            </Category>
            <Category ID="3000" Name="Valid Status, Skipped Anyways">
            </Category>
        </Categories>
    </Weakness_Catalog>
    """
    cwe.catalog = parseString(xml_content).documentElement

    # Mock parse_category_or_view to return a fake Grouping only for the non-deprecated
    fake_group = {"id": "grouping--1000"}

    def fake_parse_category_or_view(el):
        if el.getAttribute("ID") == "1000":
            return fake_group
        return None

    cwe.parse_category_or_view = MagicMock(side_effect=fake_parse_category_or_view)
    cwe.add_object = MagicMock()

    # Act
    cwe.map_categories()

    # Assert: add_object called only with our valid group
    cwe.add_object.assert_called_once_with(fake_group)


def test_parse_category_or_view_builds_grouping(cwe2stix_object):
    cwe = cwe2stix_object

    # Simulate weaknesses already parsed and in the dict
    cwe.weakness_by_id = {
        "CWE-489": MagicMock(id="weakness--b52c3e67-202f-4c89-93ba-1022812e1dcf"),
        "CWE-531": MagicMock(id="weakness--0d80e58f-63cf-40c7-bbfa-605a45dbcde0"),
        # skip the rest to see partial build
    }

    # Parse your example XML
    xml_content = """
    <Category ID="1002" Name="SFP Secondary Cluster: Unexpected Entry Points" Status="Incomplete">
        <Summary>This category identifies Software Fault Patterns (SFPs) within the Unexpected Entry Points cluster.</Summary>
        <Relationships>
            <Has_Member CWE_ID="489" View_ID="888"/>
            <Has_Member CWE_ID="491" View_ID="888"/>
            <Has_Member CWE_ID="493" View_ID="888"/>
            <Has_Member CWE_ID="500" View_ID="888"/>
            <Has_Member CWE_ID="531" View_ID="888"/>
        </Relationships>
        <Content_History>
            <Submission>
                <Submission_Name>CWE Content Team</Submission_Name>
                <Submission_Organization>MITRE</Submission_Organization>
                <Submission_Date>2014-07-29</Submission_Date>
            </Submission>
        </Content_History>
    </Category>
    """
    category_el = parseString(xml_content).documentElement

    # Also mock parse_dates and getTextFromNode
    with patch("cwe2stix.xml_utils.parse_dates") as mock_dates:

        mock_dates.return_value = ("2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z")

        # Act
        grouping = cwe.parse_category_or_view(category_el)

        # Assert
        assert grouping is not None
        assert grouping.name == "SFP Secondary Cluster: Unexpected Entry Points"
        assert grouping.description.startswith(
            "This category identifies Software Fault Patterns"
        )
        assert grouping.context == "unspecified"
        assert grouping.external_references[0].source_name == "cwe_category"
        assert grouping.external_references[0].external_id == "CWE-1002"
        # Should have exactly 4 object_refs from weaknesses found
        assert grouping.object_refs == [
            "weakness--b52c3e67-202f-4c89-93ba-1022812e1dcf",
            "weakness--0d80e58f-63cf-40c7-bbfa-605a45dbcde0",
        ]

        # test, returns None
        cwe.weakness_by_id = {}
        grouping = cwe.parse_category_or_view(category_el)
        assert grouping is None


import pytest
from unittest.mock import patch
from xml.dom.minidom import parseString


@patch("cwe2stix.cwe2stix.xml_utils.parse_dates")
@patch("cwe2stix.cwe2stix.xml_utils.parse_description")
@patch("cwe2stix.cwe2stix.map_external_references")
def test_parse_weakness_builds_weakness_sdo(
    mock_map_refs, mock_get_description, mock_parse_dates, cwe2stix_object
):
    cwe = cwe2stix_object

    # Setup return values for utilities
    mock_parse_dates.return_value = (
        "2020-01-01T00:00:00.000Z",
        "2019-01-01T00:00:00.000Z",
    )
    mock_map_refs.return_value = [
        {
            "source_name": "cwe",
            "external_id": "CWE-1023",
            "url": "http://cwe.mitre.org/data/definitions/1023.html",
        }
    ]

    # Parse the given Weakness XML snippet
    xml_content = """
    <Weakness ID="1023" Name="Incomplete Comparison with Missing Factors" Abstraction="Class" Structure="Simple" Status="Incomplete">
        <Description>The software performs a comparison between entities...</Description>
        <Extended_Description>An incomplete comparison can lead to issues.</Extended_Description>
        <Related_Weaknesses>
            <Related_Weakness Nature="ChildOf" CWE_ID="697" View_ID="1000" Ordinal="Primary"/>
        </Related_Weaknesses>
        <Modes_Of_Introduction>
            <Introduction><Phase>Implementation</Phase></Introduction>
        </Modes_Of_Introduction>
        <Common_Consequences>
            <Consequence>
                <Scope>Integrity</Scope>
                <Impact>Alter Execution Logic</Impact>
            </Consequence>
        </Common_Consequences>
    </Weakness>
    """
    weakness_el = parseString(xml_content).documentElement
    ext_ref_map = []

    # Act
    weakness_obj = cwe.parse_weakness(weakness_el)

    # Assert the main fields
    assert weakness_obj.id.startswith("weakness--")
    assert weakness_obj.name == "Incomplete Comparison with Missing Factors"
    assert weakness_obj.description == str(mock_get_description.return_value)
    assert weakness_obj.created.strftime("%Y-%m-%d") == "2019-01-01"
    assert (
        weakness_obj.modified.strftime("%Y-%m-%dT%H:%M:%SZ") == "2020-01-01T00:00:00Z"
    )
    assert weakness_obj.created_by_ref == cwe.identity_obj["id"]
    assert weakness_obj.object_marking_refs == cwe.object_marking_refs

    # Assert extensions
    assert (
        "extension-definition--31725edc-7d81-5db7-908a-9134f322284a"
        in weakness_obj.extensions
    )

    # Assert external references
    assert weakness_obj.external_references == mock_map_refs.return_value

    # Assert lists parsed
    assert isinstance(weakness_obj.common_consequences, list)
    assert isinstance(weakness_obj.modes_of_introduction, list)


def test_parse_external_references_builds_reference_map(cwe2stix_object):
    cwe = cwe2stix_object

    # Build your example XML with External_References
    xml_content = """
    <Weakness_Catalog>
        <External_References>
            <External_Reference Reference_ID="REF-1">
                <Author>NIST</Author>
                <Title>CWE - Common Weakness Enumeration</Title>
                <URL>http://nvd.nist.gov/cwe.cfm</URL>
            </External_Reference>
            <External_Reference Reference_ID="REF-2">
                <Author>OWASP</Author>
                <Title>HttpOnly</Title>
                <URL>https://www.owasp.org/index.php/HttpOnly</URL>
            </External_Reference>
            <External_Reference Reference_ID="REF-3">
                <Author>Michael Howard</Author>
                <Title>Some Bad News and Some Good News</Title>
                <Publication_Year>2002</Publication_Year>
                <URL>https://msdn.microsoft.com/en-us/library/ms972826.aspx</URL>
            </External_Reference>
        </External_References>
    </Weakness_Catalog>
    """
    catalog = parseString(xml_content).documentElement

    # Patch xml_utils functions used in parse_external_references
    with patch(
        "cwe2stix.xml_utils.firstOrNone",
        side_effect=lambda lst: lst[0] if lst else None,
    ):
        # Act
        ref_map = cwe.parse_external_references(catalog)

        # Assert the map keys
        assert set(ref_map.keys()) == {"REF-1", "REF-2", "REF-3"}

        # Check REF-1
        ref1 = ref_map["REF-1"]
        assert ref1.source_name == "NIST"
        assert ref1.description == "CWE - Common Weakness Enumeration"
        assert ref1.url == "http://nvd.nist.gov/cwe.cfm"
        assert ref1.external_id == "REF-1"

        # Check REF-2
        ref2 = ref_map["REF-2"]
        assert ref2.source_name == "OWASP"
        assert ref2.description == "HttpOnly"
        assert ref2.url == "https://www.owasp.org/index.php/HttpOnly"
        assert ref2.external_id == "REF-2"

        # Check REF-3
        ref3 = ref_map["REF-3"]
        assert ref3.source_name == "Michael Howard"
        assert ref3.description == "Some Bad News and Some Good News"
        assert ref3.url == "https://msdn.microsoft.com/en-us/library/ms972826.aspx"
        assert ref3.external_id == "REF-3"


def test_map_external_references_builds_refs_correctly():
    # Setup fake reference map
    reference_map = {
        "REF-123": {
            "source_name": "nist",
            "external_id": "SP-800",
            "description": "NIST Guide",
        },
    }

    # XML with References, Taxonomy_Mapping and Related_Attack_Pattern
    xml_content = """
    <Weakness ID="1023">
        <References>
            <Reference External_Reference_ID="REF-123"/>
        </References>
        <Taxonomy_Mappings>
            <Taxonomy_Mapping Taxonomy_Name="OWASP Top Ten">
                <Entry_ID>5</Entry_ID>
                <Entry_Name>Broken Access Control</Entry_Name>
            </Taxonomy_Mapping>
        </Taxonomy_Mappings>
        <Related_Attack_Patterns>
            <Related_Attack_Pattern CAPEC_ID="88"/>
        </Related_Attack_Patterns>
    </Weakness>
    """
    weakness_el = parseString(xml_content).documentElement

    # Act
    refs = map_external_references("1023", weakness_el, reference_map)

    # Assert always includes the CWE self-reference
    cwe_ref = next((r for r in refs if r.source_name == "cwe"), None)
    assert cwe_ref is not None
    assert cwe_ref.external_id == "CWE-1023"
    assert cwe_ref.url == "http://cwe.mitre.org/data/definitions/1023.html"

    # Assert includes mapped Reference from <References>
    nist_ref = next((r for r in refs if r.get("source_name") == "nist"), None)
    assert nist_ref is not None
    assert nist_ref["external_id"] == "SP-800"

    # Assert includes Taxonomy_Mapping
    taxonomy_ref = next((r for r in refs if r["source_name"] == "OWASP Top Ten"), None)
    assert taxonomy_ref is not None
    assert taxonomy_ref.external_id == "5"
    assert taxonomy_ref.description == "Broken Access Control"

    # Assert includes CAPEC
    capec_ref = next((r for r in refs if r["source_name"] == "capec"), None)
    assert capec_ref is not None
    assert capec_ref.external_id == "CAPEC-88"
    assert capec_ref.url == "https://capec.mitre.org/data/definitions/88.html"


@patch("cwe2stix.cwe2stix.zipfile.ZipFile")
@patch("cwe2stix.cwe2stix.requests.get")
@pytest.mark.parametrize("writes_files", [True, False])
def test_process_download_downloads_and_extracts(
    mock_get, mock_zipfile, cwe2stix_object, writes_files
):
    cwe = cwe2stix_object
    cwe.writes_files = writes_files  # test also the file writing branch

    # Setup mocks
    fake_zip_content = b"fake zip bytes"
    mock_response = MagicMock()
    mock_response.content = fake_zip_content
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    # Setup zipfile mock
    mock_zip_ref = MagicMock()
    mock_file = MagicMock()
    mock_file.is_dir.return_value = False
    mock_file.filename = "somefile.xml"
    mock_zip_ref.filelist = [mock_file]
    mock_zip_ref.read.return_value = b"<xml>data</xml>"

    mock_zipfile.return_value.__enter__.return_value = mock_zip_ref

    # Patch Path.mkdir and Path.write_bytes so no real I/O happens
    with patch("pathlib.Path.mkdir") as mock_mkdir, patch(
        "pathlib.Path.write_bytes"
    ) as mock_write_bytes:

        # Act
        cwe.process_download()

    # Asserts on requests
    mock_get.assert_called_once_with(cwe.url)
    mock_response.raise_for_status.assert_called_once()

    # Asserts on zip extraction
    mock_zipfile.assert_called_once()
    mock_zip_ref.extractall.assert_called_once_with(config.raw_data_xml)

    # Should have read xml_bytes from the zip
    assert cwe.xml_bytes == b"<xml>data</xml>"

    # Should write to filesystem
    if writes_files:
        mock_mkdir.assert_called_once()
        mock_write_bytes.assert_called_once_with(b"<xml>data</xml>")
    else:
        mock_mkdir.assert_not_called()
        mock_write_bytes.assert_not_called()


def test_identity_ref(cwe2stix_object):
    assert (
        cwe2stix_object.identity_obj["id"]
        == "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"
    )
