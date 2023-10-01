import pathlib
import logging
from spdx_tools.spdx.parser import parse_anything, error
from spdx_tools.spdx import model as spdx_mod

from spdx_visualizer.utils import logger


class SPDXDocument:
    annotations: dict[str, spdx_mod.Annotation]
    creation_info: spdx_mod.CreationInfo
    extracted_licensing: dict[str, spdx_mod.ExtractedLicensingInfo]
    packages: dict[str, spdx_mod.Package]
    files: dict[str, spdx_mod.File]
    relationships: dict[str, spdx_mod.Relationship]
    snippets: dict[str, spdx_mod.Snippet]

    _document: spdx_mod.Document
    _logger: logging.Logger

    def __init__(self, doc_file_path: pathlib.Path) -> None:
        self._logger = logger.getLogger(__name__)
        self._document = self._load_document(doc_file_path)
        self._decompose_document()

    def _load_document(self, doc_file_path: pathlib.Path) -> spdx_mod.Document:
        self._logger.debug("Reading SPDX file: %s", doc_file_path)
        try:
            doc = parse_anything.parse_file(doc_file_path.as_posix())
        except error.SPDXParsingError as excpt:
            self._logger.error("Error parsing SPDX file: %s", doc_file_path)
            for error_str in excpt.get_messages():
                self._logger.error("\t- Parsing Error: %s", error_str)
        if doc is None:
            raise ValueError("Error parsing %s", doc_file_path)
        return doc

    def _decompose_document(self):
        self.creation_info = self._document.creation_info
        self.annotations = {
            annotation.spdx_id: annotation for annotation in self._document.annotations
        }
        # TODO: Add this
        # self.extracted_licensing = {
        #     info.spdx_id: info for info in self._document.extracted_licensing_info
        # }
        self.files = {file.spdx_id: file for file in self._document.files}
        self.snippets = {
            snippet.spdx_id: snippet for snippet in self._document.snippets
        }
        self.packages = {
            package.spdx_id: package for package in self._document.packages
        }
        self.relationships = {
            relationship.spdx_id: relationship
            for relationship in self._document.relationship
        }
