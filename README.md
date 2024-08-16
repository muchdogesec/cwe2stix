# cwe2stix

A command line tool that turns MITRE CWEs into STIX 2.1 Objects.

## Before you get started

If you do not want to backfill, maintain, or support your own CWE STIX objects check out CTI Butler which provides a fully manage database of these objects and more!

https://www.ctibutler.com/

## Overview

CWEs are [Common Weakness Enumerations (CWE's)](https://cwe.mitre.org/). CWE's are a community-developed list of software and hardware weakness types managed MITRE. They serve as a common language as a baseline for weakness identification, mitigation, and prevention efforts.

For example, [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html).

We had a requirement to have an up-to-date copy of MITRE CWEs in STIX 2.1 format, like already exists and maintained by MITRE for ATT&CK (e.g. [Enterprise](https://github.com/mitre/cti/tree/master/enterprise-attack)) and [CAPEC](https://github.com/mitre/cti/tree/master/capec/2.1) on GitHub.

The code in this repository is a similar to the MITRE implementations for ATT&CK and CAPEC that;

1. Downloads latest CWE XML
2. Checks version of CWE XML
3. Converts them to STIX 2.1 Objects, if new version
4. Stores the STIX 2.1 Objects in the file store

## Installing the script

To install cwe2stix;

```shell
# clone the latest code
git clone https://github.com/muchdogesec/cwe2stix
# create a venv
cd cwe2stix
python3 -m venv cwe2stix-venv
source cwe2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

## Running the script

```shell
python3 cwe2stix.py --version <CWE VERSION NUMBER>
```

* `--version` (optional): by default the script will download the latest available CWE file from the CWE website. If you want a specific version, you can pass the `--version` flag. e.g. `--version 4.13`. Note, only versions >= 4.5 are currently supported by this script.

For example, to download the 4.13 version of CWEs;

```shell
python3 cwe2stix.py --version 4.13
```

If no `--version` passed, the latest CWE file located at `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` will be downloaded.

On each script run, the objects and bundle will be removed (if difference detected in version), and regenerated.

To handle versions, on the first run a `CWE_VERSION` file is created, listing the version of CWEs in the `stix2_objects` directory. On subsequent runs, this version value will changes based on the version of CWEs converted.

## Mapping information

### Data download

[MITRE maintain an XML file with the full CWE definitions here](https://cwe.mitre.org/data/downloads.html). This appears to be the best machine readable format to use based on the other alternatives MITRE use to distribute this data (HTML and PDF).

This XML file is what cwe2stix uses to generate the STIX objects.

A high-level overview of the way the STIX objects are linked can be viewed here;

https://miro.com/app/board/uXjVKpOg6bM=/

### Identity / Marking Definition / Extension Definition

* Identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/cwe2stix.json
* Marking Definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/cwe2stix.json
* Extension Definition: https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/sdos/weakness.json

### Weakness

The key object to represent CWEs is a Weakness (this is a custom STIX objects):

```json
{
    "type": "weakness",
    "spec_version": "2.1",
    "id": "weakness--<UUIDV5 GENERATION LOGIC>",
    "name": "<CWE NAME>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<Weaknesses.Weakness.Submission_Date>",
    "modified": "<Weaknesses.Weakness.Modification_Date> (latest date)",
    "description": "<Weaknesses.Weakness.Description> <Weaknesses.Weakness.Extended_Description>",
	"modes_of_introduction": ["Modes_Of_Introduction.Introduction.Phase"],
	"likelihood_of_exploit": "Likelihood_Of_Exploit",
	"common_consequences": ["Common_Consequences.Consequence.Scope"],
	"detection_methods": ["Detection_Methods.Detection_Method.Method"],
    "external_references": [
        {
         	"source_name": "cwe",
          	"external_id": "CWE-<CWE ID>",
          	"url": "http://cwe.mitre.org/data/definitions/<CWE ID>.html"
        },
        {
         	"source_name": "<External_Reference.author>, <External_Reference.author>",
          	"description": "<External_Reference.title>",
          	"url": "<External_Reference.URL>",
            "external_id": "<Weaknesses.Weakness.External_Reference_ID>",
        },
        {
         	"source_name": "<Weaknesses.Weakness.Taxonomy_Mappings.Taxonomy_Name>",
          	"external_id": "<Weaknesses.Weakness.Taxonomy_Mappings.Entry_ID>",
          	"description": "<Weaknesses.Weakness.Taxonomy_Mappings.Entry_Name>"
        },
        {
         	"source_name": "capec",
          	"external_id": "CAPEC-<Weaknesses.Weakness.Related_Attack_Patterns.Related_Attack_Pattern>",
          	"url": "https://capec.mitre.org/data/definitions/<Weaknesses.Weakness.Related_Attack_Patterns.Related_Attack_Pattern>.html"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINITION OBJECT>"
    ],
    "extensions": {
        "<IMPORTED EXTENSION DEFINITION>": {
            "extension_type": "new-sdo"
        }
    }
}
```

Note, the `created` field relies on you importing versions in order. Usually this is a non-issue, but if you plan on backfilling data, YOU MUST import them in order (earliest first).

To generate the id, a UUIDv5 is generated using the namespace `d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b` and CWE-ID. e.g. CWE-102 = `ad5b3e38-fdf2-5c97-90da-30dad0f1f016` = `weakness--ad5b3e38-fdf2-5c97-90da-30dad0f1f016`

### Relationships

Inside each weakness ID is also a property `Weaknesses.Related_Weaknesses`. For example, for CWE-521;

```xml
<Related_Weaknesses>
    <Related_Weakness Nature="ChildOf" CWE_ID="1391" View_ID="1000" Ordinal="Primary"/>
    <Related_Weakness Nature="ChildOf" CWE_ID="287" View_ID="1003" Ordinal="Primary"/>
</Related_Weaknesses>
```

cwe2stix models these using [STIX 2.1 Relationship Objects](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_cqhkqvhnlgfh) as follows;

```json
{
 	"type": "relationship",
 	"spec_version": "2.1",
 	"id": "relationship--<UUIDV5 GENERATION LOGIC>",
 	"created_by_ref": "<IMPORTED IDENTITY OBJECT>",
 	"created": "<CREATED TIME OF MOST RECENT CWE OBJECT IN PAIR>",
 	"modified": "<CREATED TIME OF MOST RECENT CWE OBJECT IN PAIR>",
 	"relationship_type": "<Related_Weakness Nature>",
 	"source_ref": "weakness--<CURRENT WEAKNESS>",
 	"target_ref": "weakness--<Weaknesses.Weakness.Related_Weaknesses.Related_Weakness.CWE_ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINITION OBJECT>"
    ],
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b` and `<Related_Weakness Nature>+SOURCE_CWEID+TARGET_CWEID`.

e.g. `CanPrecede+CWE-1423+CWE-1102` = `7a612ea9-a08b-54bd-9e21-570509ba5d25` = `relationship--7a612ea9-a08b-54bd-9e21-570509ba5d25`

### Grouping

The CWE XML also contains category entries. e.g.

```xml
<Category ID="1020" Name="Verify Message Integrity" Status="Draft">
         <Summary>Weaknesses in this category are related to the design and architecture of a system's data integrity components. Frequently these deal with ensuring integrity of data, such as messages, resource files, deployment files, and configuration files. The weaknesses in this category could lead to a degradation of data integrity quality if they are not addressed when designing or implementing a secure architecture.</Summary>
         <Relationships>
            <Has_Member CWE_ID="353" View_ID="1008"/>
            <Has_Member CWE_ID="354" View_ID="1008"/>
            <Has_Member CWE_ID="390" View_ID="1008"/>
            <Has_Member CWE_ID="391" View_ID="1008"/>
            <Has_Member CWE_ID="494" View_ID="1008"/>
            <Has_Member CWE_ID="565" View_ID="1008"/>
            <Has_Member CWE_ID="649" View_ID="1008"/>
            <Has_Member CWE_ID="707" View_ID="1008"/>
            <Has_Member CWE_ID="755" View_ID="1008"/>
            <Has_Member CWE_ID="924" View_ID="1008"/>
         </Relationships>
         <References>
            <Reference External_Reference_ID="REF-9"/>
            <Reference External_Reference_ID="REF-10" Section="pages 69 - 78"/>
         </References>
         <Mapping_Notes>
            <Usage>Prohibited</Usage>
            <Rationale>This entry is a Category. Using categories for mapping has been discouraged since 2019. Categories are informal organizational groupings of weaknesses that can help CWE users with data aggregation, navigation, and browsing. However, they are not weaknesses in themselves.</Rationale>
            <Comments>See member weaknesses of this category.</Comments>
            <Reasons>
               <Reason Type="Category"/>
            </Reasons>
         </Mapping_Notes>
         <Content_History>
            <Submission>
               <Submission_Name>Joanna C.S. Santos, Mehdi Mirakhorli</Submission_Name>
               <Submission_Date>2017-06-22</Submission_Date>
               <Submission_Version>2.12</Submission_Version>
               <Submission_ReleaseDate>2017-11-08</Submission_ReleaseDate>
               <Submission_Comment>Provided the catalog, Common Architectural Weakness Enumeration (CAWE), and research papers for this view.</Submission_Comment>
            </Submission>
                <Modification>
                    <Modification_Name>CWE Content Team</Modification_Name>
                    <Modification_Organization>MITRE</Modification_Organization>
                    <Modification_Date>2023-04-27</Modification_Date>
                    <Modification_Comment>updated Mapping_Notes</Modification_Comment>
                </Modification>
                <Modification>
                    <Modification_Name>CWE Content Team</Modification_Name>
                    <Modification_Organization>MITRE</Modification_Organization>
                    <Modification_Date>2023-06-29</Modification_Date>
                    <Modification_Comment>updated Mapping_Notes</Modification_Comment>
                </Modification>
         </Content_History>
      </Category>
```

Grouping SDOs are also used to represent CWE Categories (e.g. OWASP Top Ten 2004).

Grouping SDOs are modelled from CWE entries as follows

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUIDV5 LOGIC>",
    "created_by_ref": "<IMPORTED IDENTITY OBJECT>",
    "created": "<Content_History.Submission_Date>",
    "modified": "<Modification.Modificaton Date> (latest)",
    "name": "<CATEGORY.NAME>",
    "description": "<CATEGORY.SUMMARY>",
    "context": "unspecified",
    "external_references": [
        {
            "source_name": "cwe_category",
            "external_id": "<CWE CATEGORY ID>"
        },
        {
            "source_name": "<External_Reference.author>, <External_Reference.author>",
            "description": "<External_Reference.title>",
            "url": "<External_Reference.URL>",
            "external_id": "<Weaknesses.Weakness.External_Reference_ID>",
        },
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<IMPORTED MARKING DEFINITION OBJECT>"
    ],
    "object_refs": [
        "<STIX IDs OF ALL CWEs LISTED IN CATEGORY.Relationships>"
    ]
}
```

To generate the id of the SDO, a UUIDv5 is generated using the namespace `d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b` and `name` field, e.g. `SFP Primary Cluster: Malware` = `0523bdc3-24d8-5634-9353-14def9f5cfcf` = `grouping--0523bdc3-24d8-5634-9353-14def9f5cfcf`

To demonstrate the `object_refs` payload, in example for category 1020 above, the `object_refs` list would contain the STIX vulnerability IDs for; CWE_ID="353" CWE_ID="354" CWE_ID="390" CWE_ID="391" CWE_ID="494" CWE_ID="565 CWE_ID="649" CWE_ID="707" CWE_ID="755" CWE_ID="924".

In some cases related weakness do not exist, as the CWE record does not exist in the dataset. For example, Category 1001 has a referenced `Weakness ID="227"`, however, there is no CWE-227 in the CWE dictionary. 

```xml
      <Category ID="1001" Name="SFP Secondary Cluster: Use of an Improper API" Status="Incomplete">
         <Summary>This category identifies Software Fault Patterns (SFPs) within the Use of an Improper API cluster (SFP3).</Summary>
         <Relationships>
            <Has_Member CWE_ID="111" View_ID="888"/>
            <Has_Member CWE_ID="227" View_ID="888"/>
            <Has_Member CWE_ID="242" View_ID="888"/>
```

If a reference to a Vulnerability that does not exist (e.g. Weakness ID="227") is made, the entry is ignored in the Grouping `object_refs` dictionary.

### Bundle

cwe2stix also creates a STIX 2.1 Bundle JSON object containing all the other STIX 2.1 Objects created at each run. The Bundle takes the format;

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5 GENERATION LOGIC>",
    "objects": [
   		"<ALL STIX JSON OBJECTS>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b` and a md5 hash of all objects sorted in the bundle.

Unlike the other STIX Objects, this means on every update a new bundle ID will be generated if any difference in objects or properties is observed.

## Backfill old versions

Here is a quick example of how to create bundles representing different versions of CWEs for comparison;

```shell
python3 cwe2stix.py --version 4.5 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_5.json && \
python3 cwe2stix.py --version 4.6 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_6.json && \
python3 cwe2stix.py --version 4.7 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_7.json && \
python3 cwe2stix.py --version 4.8 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_8.json && \
python3 cwe2stix.py --version 4.9 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_9.json && \
python3 cwe2stix.py --version 4.10 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_10.json && \
python3 cwe2stix.py --version 4.11 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_11.json && \
python3 cwe2stix.py --version 4.12 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_12.json && \
python3 cwe2stix.py --version 4.13 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_13.json && \
python3 cwe2stix.py --version 4.14 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_14.json && \
python3 cwe2stix.py --version 4.15 && mv stix2_objects/cwe-bundle.json bundle_store/cwe-bundle-v4_15.json
```

Note, [you can easily download historic CWE data from our cti_knowledge_base repository so you don't have to run this script](https://github.com/muchdogesec/cti_knowledge_base_store).

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [MITRE CWE site](https://cwe.mitre.org/)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).