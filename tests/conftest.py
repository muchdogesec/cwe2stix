
import copy
import pytest

from cwe2stix.cwe2stix import Cwe2Stix


@pytest.fixture
def cwe2stix_object():
    retval = Cwe2Stix(version='4.17')
    yield retval
    # retval.clean_data_dir()
    retval.clean_filesystem()
