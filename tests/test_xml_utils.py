from datetime import UTC, datetime
from xml.dom.minidom import parseString
from cwe2stix import xml_utils
from unittest.mock import patch


def test_parse_dates_extracts_submission_and_modification():

    xml = """
    <Weakness>
        <Content_History>
            <Submission>
                <Submission_Date>2014-01-01</Submission_Date>
            </Submission>
            <Modification>
                <Modification_Date>2015-05-05</Modification_Date>
            </Modification>
            <Modification>
                <Modification_Date>2016-06-06</Modification_Date>
            </Modification>
        </Content_History>
    </Weakness>
    """
    el = parseString(xml).documentElement
    modified, submitted = xml_utils.parse_dates(el)

    assert submitted == datetime(2014, 1, 1, tzinfo=UTC)
    # should use the *latest* Modification_Date
    assert modified == datetime(2016, 6, 6, tzinfo=UTC)

def test_parse_dates_with_submission_and_no_modification():

    xml = """
    <Weakness>
        <Content_History>
            <Submission>
                <Submission_Date>2014-01-01</Submission_Date>
            </Submission>
        </Content_History>
    </Weakness>
    """
    el = parseString(xml).documentElement
    modified, submitted = xml_utils.parse_dates(el)

    assert submitted == datetime(2014, 1, 1, tzinfo=UTC)
    # should use submission date as modified
    assert modified == submitted

@patch("cwe2stix.xml_utils.utils.parse_datetime")
def test_parse_dates_returns_none_on_missing_history(mock_parse_dt):
    el = parseString("<Weakness></Weakness>").documentElement
    modified, submitted = xml_utils.parse_dates(el)
    assert modified is None and submitted is None


def test_parse_common_consequences_returns_scopes():
    xml = """
    <Weakness>
        <Common_Consequences>
            <Consequence><Scope>Integrity</Scope><Scope>Confidentiality</Scope></Consequence>
            <Consequence><Scope>Access Control</Scope></Consequence>
        </Common_Consequences>
    </Weakness>
    """
    el = parseString(xml).documentElement
    scopes = xml_utils.parse_common_consequences(el)
    assert scopes == ["Integrity", "Confidentiality", "Access Control"]

def test_parse_common_consequences_empty_when_missing():
    el = parseString("<Weakness></Weakness>").documentElement
    assert xml_utils.parse_common_consequences(el) == []


def test_parse_detection_methods_extracts_methods():
    xml = """
    <Weakness>
        <Detection_Methods>
            <Detection_Method>
                <Method>Static Analysis</Method>
            </Detection_Method>
            <Detection_Method>
                <Method>Fuzz Testing</Method>
            </Detection_Method>
        </Detection_Methods>
    </Weakness>
    """
    el = parseString(xml).documentElement
    methods = xml_utils.parse_detection_methods(el)
    assert methods == ["Static Analysis", "Fuzz Testing"]

def test_parse_detection_methods_empty_when_missing():
    el = parseString("<Weakness></Weakness>").documentElement
    assert xml_utils.parse_detection_methods(el) == []



def test_parse_modes_of_introduction_phases():
    xml = """
    <Weakness>
         <Modes_Of_Introduction>
            <Introduction>
               <Phase>Architecture and Design</Phase>
               <Note>This weakness is introduced during the design of an application when the architect does not specify that a linked external document should not be able to alter the location of the calling page.</Note>
            </Introduction>
            <Introduction>
               <Phase>Implementation</Phase>
               <Note>This weakness is introduced during the coding of an application when the developer does not include the noopener and/or noreferrer value for the rel attribute.</Note>
            </Introduction>
         </Modes_Of_Introduction>
    </Weakness>
    """
    el = parseString(xml).documentElement
    phases = xml_utils.parse_modes_of_introduction(el)
    assert phases == ["Architecture and Design", "Implementation"]

def test_parse_modes_of_introduction_empty_when_missing():
    el = parseString("<Weakness></Weakness>").documentElement
    assert xml_utils.parse_modes_of_introduction(el) == []



def test_parse_description_includes_extended_description():
    xml = """
    <Weakness xmlns:xhtml="http://www.w3.org/1999/xhtml">
        <Description>
            The software creates an immutable text string using string concatenation operations.
        </Description>
        <Extended_Description>
            <xhtml:p>
                When building a string via a looping feature (e.g., a FOR or WHILE loop), the use of += to append to the existing string will result in the creation of a new object with each iteration. This programming pattern can be inefficient in comparison with use of text buffer data elements. This issue can make the software perform more slowly. If the relevant code is reachable by an attacker, then this could be influenced to create performance problem.
            </xhtml:p>
        </Extended_Description>
    </Weakness>
    """
    el = parseString(xml).documentElement
    desc = xml_utils.parse_description(el)
    assert "The software creates an immutable text string using string concatenation operations." in desc
    assert "When building a string via a looping feature" in desc
    assert "Extended_Description" not in desc
    assert "<span>" in desc  # confirms tag rename to span

def test_parse_description_only_simple():
    xml = "<Weakness><Description>Basic only</Description></Weakness>"
    el = parseString(xml).documentElement
    desc = xml_utils.parse_description(el)
    assert desc == "Basic only"
