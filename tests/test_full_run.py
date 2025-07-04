import contextlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from stix2 import FileSystemStore

from cwe2stix import config
from cwe2stix.cwe2stix import Cwe2Stix


def test_full_run():
    cwe_bundle_path = Path('stix2_objects/cwe-bundle.json')
    with contextlib.suppress(Exception):
        os.remove(cwe_bundle_path)
    cwe2stix = Cwe2Stix(version=None)
    cwe2stix.run_and_write()
    assert cwe_bundle_path.exists()
    assert cwe2stix.version == Path(config.cwe2stix_version_filename).read_text().strip()