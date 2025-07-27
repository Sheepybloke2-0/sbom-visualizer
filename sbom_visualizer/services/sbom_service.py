"""
Main SBOM service for orchestrating SBOM operations.

Provides high-level interface for parsing, analyzing, and verifying SBOM files.
"""

import logging
from pathlib import Path
from typing import Optional

from ..config import settings
from ..core.analyzer import SBOMAnalyzer
from ..core.dependency_viewer import DependencyViewer
from ..core.package_checker import PackageChecker
from ..core.parser import SBOMParser
from ..core.verifier import SBOMVerifier
from ..exceptions import (
    SBOMAnalysisError,
    SBOMFileError,
    SBOMParseError,
    SBOMVerificationError,
)
from ..models.sbom_models import (
    AnalysisResult,
    DependencyTree,
    PackageInfo,
    SBOMData,
    VerificationResult,
)

logger = logging.getLogger(__name__)


class SBOMService:
    """Service layer for SBOM operations."""

    def __init__(
        self,
        parser: SBOMParser = None,
        analyzer: SBOMAnalyzer = None,
        verifier: SBOMVerifier = None,
        dependency_viewer: DependencyViewer = None,
        package_checker: PackageChecker = None,
    ):
        """Initialize the SBOM service with core components."""
        self.parser = parser or SBOMParser()
        self.analyzer = analyzer or SBOMAnalyzer()
        self.verifier = verifier or SBOMVerifier()
        self.dependency_viewer = dependency_viewer or DependencyViewer()
        self.package_checker = package_checker or PackageChecker()

    def parse_sbom(self, file_path: Path) -> SBOMData:
        """
        Parse SBOM file and return structured data.

        Args:
            file_path: Path to the SBOM file

        Returns:
            Parsed SBOM data

        Raises:
            SBOMFileError: If file cannot be read
            SBOMParseError: If parsing fails
        """
        try:
            logger.info(f"Parsing SBOM file: {file_path}")

            # Validate file exists and is readable
            if not file_path.exists():
                raise SBOMFileError(f"File not found: {file_path}")

            if not file_path.is_file():
                raise SBOMFileError(f"Path is not a file: {file_path}")

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > settings.max_file_size:
                raise SBOMFileError(
                    f"File too large: {file_size} bytes (max: {settings.max_file_size})"
                )

            # Parse the file
            sbom_data = self.parser.parse_file(file_path)
            logger.info(
                f"Successfully parsed SBOM with {len(sbom_data.packages)} packages"
            )

            return sbom_data

        except (FileNotFoundError, PermissionError) as e:
            raise SBOMFileError(f"File access error: {e}")
        except Exception as e:
            raise SBOMParseError(f"Failed to parse SBOM file: {e}")

    def analyze_sbom(self, sbom_data: SBOMData) -> AnalysisResult:
        """
        Analyze SBOM data and return comprehensive analysis.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Analysis result with statistics and recommendations

        Raises:
            SBOMAnalysisError: If analysis fails
        """
        try:
            logger.info(f"Analyzing SBOM: {sbom_data.document_name}")
            analysis_result = self.analyzer.analyze(sbom_data)
            logger.info(
                f"Analysis completed with {analysis_result.total_packages} packages"
            )
            return analysis_result

        except Exception as e:
            raise SBOMAnalysisError(f"Failed to analyze SBOM: {e}")

    def verify_sbom(self, sbom_data: SBOMData) -> VerificationResult:
        """
        Verify SBOM data for compliance and completeness.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Verification result with issues and warnings

        Raises:
            SBOMVerificationError: If verification fails
        """
        try:
            logger.info(f"Verifying SBOM: {sbom_data.document_name}")
            verification_result = self.verifier.verify(sbom_data)
            logger.info(
                f"Verification completed with {len(verification_result.issues)} issues"
            )
            return verification_result

        except Exception as e:
            raise SBOMVerificationError(f"Failed to verify SBOM: {e}")

    def get_dependency_tree(self, sbom_data: SBOMData) -> DependencyTree:
        """
        Generate dependency tree from SBOM data.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dependency tree structure
        """
        try:
            logger.info(f"Generating dependency tree for: {sbom_data.document_name}")
            dependency_tree = self.dependency_viewer.generate_tree(sbom_data)
            logger.info(
                f"Dependency tree generated with {dependency_tree.total_dependencies} dependencies"
            )
            return dependency_tree

        except Exception as e:
            logger.error(f"Failed to generate dependency tree: {e}")
            raise SBOMAnalysisError(f"Failed to generate dependency tree: {e}")

    def get_package_info(
        self, sbom_data: SBOMData, package_name: str
    ) -> Optional[PackageInfo]:
        """
        Get detailed information about a specific package.

        Args:
            sbom_data: Parsed SBOM data
            package_name: Name of the package to find

        Returns:
            Package information or None if not found
        """
        try:
            logger.info(f"Getting package info for: {package_name}")
            package_info = self.package_checker.get_package_info(
                sbom_data, package_name
            )

            if package_info:
                logger.info(f"Found package: {package_info.name}")
            else:
                logger.info(f"Package not found: {package_name}")

            return package_info

        except Exception as e:
            logger.error(f"Failed to get package info: {e}")
            raise SBOMAnalysisError(f"Failed to get package info: {e}")

    def analyze_and_verify(
        self, file_path: Path
    ) -> tuple[AnalysisResult, VerificationResult]:
        """
        Parse, analyze, and verify an SBOM file in one operation.

        Args:
            file_path: Path to the SBOM file

        Returns:
            Tuple of (analysis_result, verification_result)
        """
        try:
            # Parse and analyze SBOM
            sbom_data = self.parser.parse_file(file_path)
            analysis_result = self.analyzer.analyze(sbom_data)
            verification_result = self.verifier.verify(sbom_data)

            return analysis_result, verification_result

        except Exception as e:
            logger.error(f"Failed to analyze and verify SBOM: {e}")
            raise
