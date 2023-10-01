import pathlib
import pytest

from spdx_tools.spdx.parser import error

from spdx_visualizer.spdx_parser import SPDXDocument


class TestSpdxDoc:
    VALID_TEST_FILE: pathlib.Path = pathlib.Path("files/valid_spdx.spdx.json")
    INVALID_TEST_FILE: pathlib.Path = pathlib.Path("files/invalid_spdx.spdx.json")

    def test_document_load_success(self):
        doc = SPDXDocument._load_document(self.VALID_TEST_FILE)
        assert doc

    def test_document_load_failed(self):
        with pytest.raises(error.SPDXParsingError):
            doc = SPDXDocument._load_document(self.INVALID_TEST_FILE)
