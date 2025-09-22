"""Main module."""

import io

from xml.dom.minidom import Element
from cwe2stix import utils


def getTextFromNode(nodelist: list[Element]):
    if not nodelist:
        return ""
    if not isinstance(nodelist, list):
        nodelist = nodelist.childNodes
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE or node.nodeType == node.CDATA_SECTION_NODE:
            rc.append(node.data)
    return "".join(rc)


def firstOrNone(elemlist: list[Element]):
    if not elemlist:
        return None
    return elemlist[0]


def parse_dates(el: Element):
    history_el = firstOrNone(el.getElementsByTagName("Content_History"))
    if not history_el:
        return None, None
    submission_date = getTextFromNode(
        firstOrNone(history_el.getElementsByTagName("Submission_Date"))
    )
    assert submission_date
    modification_date = getTextFromNode(
        firstOrNone(history_el.getElementsByTagName("Modification_Date")[::-1])
    )
    modification_date = modification_date or submission_date
    return utils.parse_datetime(modification_date), utils.parse_datetime(
        submission_date
    )


def parse_common_consequences(weakness_el: Element):
    common_consequences = []
    cons_el = firstOrNone(weakness_el.getElementsByTagName("Common_Consequences"))
    if not cons_el:
        return common_consequences
    for el in cons_el.getElementsByTagName("Consequence"):
        for scope in el.getElementsByTagName("Scope"):
            common_consequences.append(getTextFromNode(scope))
    return common_consequences


def parse_detection_methods(weakness_el: Element):
    detection_methods = []
    det_el = firstOrNone(weakness_el.getElementsByTagName("Detection_Methods"))
    if not det_el:
        return detection_methods
    for el in det_el.getElementsByTagName("Method"):
        detection_methods.append(getTextFromNode(el))
    return detection_methods


def parse_modes_of_introduction(weakness_el: Element):
    mode_of_introduction_phases = []
    modes_el = firstOrNone(weakness_el.getElementsByTagName("Modes_Of_Introduction"))
    if not modes_el:
        return mode_of_introduction_phases
    for el in modes_el.getElementsByTagName("Phase"):
        mode_of_introduction_phases.append(getTextFromNode(el))
    return mode_of_introduction_phases


def parse_description(weakness_el: Element):
    description = getTextFromNode(
        firstOrNone(weakness_el.getElementsByTagName("Description"))
    )
    if extended_el := firstOrNone(
        weakness_el.getElementsByTagName("Extended_Description")
    ):
        buf = io.StringIO()
        extended_el.writexml(buf)
        buf.seek(0)
        extended_description = (
            buf.getvalue()
            .replace("xhtml:", "")
            .replace("Extended_Description>", "span>")
        )
        description = f"{description}\n-------------\n{extended_description}"
    return description
