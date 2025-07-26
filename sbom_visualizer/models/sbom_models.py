"""
Core data models for SBOM Visualizer.

Defines the data structures used throughout the application using Pydantic for
type safety and automatic validation.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SBOMFormat(str, Enum):
    """Supported SBOM formats."""

    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SWID = "swid"


class License(BaseModel):
    """License information for a package."""

    identifier: str = Field(
        ..., description="License identifier (e.g., MIT, Apache-2.0)"
    )
    name: Optional[str] = Field(None, description="Human-readable license name")
    url: Optional[str] = Field(None, description="URL to license text")
    is_osi_approved: Optional[bool] = Field(
        None, description="Whether license is OSI approved"
    )


class Dependency(BaseModel):
    """Dependency relationship between packages."""

    package_id: str = Field(..., description="ID of the dependent package")
    package_name: str = Field(..., description="Name of the dependent package")
    version_constraint: Optional[str] = Field(None, description="Version constraint")
    relationship_type: str = Field(..., description="Type of dependency relationship")


class Vulnerability(BaseModel):
    """Vulnerability information."""

    cve_id: Optional[str] = Field(None, description="CVE identifier")
    severity: Optional[str] = Field(None, description="Severity level")
    description: Optional[str] = Field(None, description="Vulnerability description")
    affected_versions: Optional[List[str]] = Field(
        None, description="Affected version ranges"
    )


class Package(BaseModel):
    """Package information from SBOM."""

    id: str = Field(..., description="Unique package identifier")
    name: str = Field(..., description="Package name")
    version: Optional[str] = Field(None, description="Package version")
    description: Optional[str] = Field(None, description="Package description")
    licenses: List[License] = Field(
        default_factory=list, description="Package licenses"
    )
    dependencies: List[Dependency] = Field(
        default_factory=list, description="Package dependencies"
    )
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Known vulnerabilities"
    )
    purl: Optional[str] = Field(None, description="Package URL (PURL)")
    supplier: Optional[str] = Field(None, description="Package supplier/vendor")
    homepage: Optional[str] = Field(None, description="Package homepage URL")
    source_info: Optional[str] = Field(None, description="Source information")
    checksums: Dict[str, str] = Field(
        default_factory=dict, description="Package checksums"
    )


class SBOMData(BaseModel):
    """Complete SBOM data structure."""

    format: SBOMFormat = Field(..., description="SBOM format")
    version: str = Field(..., description="SBOM format version")
    document_name: str = Field(..., description="SBOM document name")
    document_namespace: Optional[str] = Field(None, description="Document namespace")
    created: datetime = Field(..., description="Creation timestamp")
    creator: str = Field(..., description="SBOM creator")
    packages: List[Package] = Field(
        default_factory=list, description="List of packages"
    )
    relationships: List[Dict[str, Any]] = Field(
        default_factory=list, description="Package relationships"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )


class VerificationResult(BaseModel):
    """Result of SBOM verification."""

    is_valid: bool = Field(..., description="Whether SBOM is valid")
    issues: List[str] = Field(
        default_factory=list, description="List of verification issues"
    )
    warnings: List[str] = Field(default_factory=list, description="List of warnings")
    format_detected: Optional[SBOMFormat] = Field(
        None, description="Detected SBOM format"
    )
    version_detected: Optional[str] = Field(None, description="Detected format version")


class AnalysisResult(BaseModel):
    """Result of SBOM analysis."""

    total_packages: int = Field(..., description="Total number of packages")
    unique_licenses: List[str] = Field(
        default_factory=list, description="Unique license identifiers"
    )
    license_distribution: Dict[str, int] = Field(
        default_factory=dict, description="License usage distribution"
    )
    dependency_depth: Dict[str, int] = Field(
        default_factory=dict, description="Dependency depth analysis"
    )
    vulnerability_summary: Dict[str, int] = Field(
        default_factory=dict, description="Vulnerability summary by severity"
    )
    completeness_score: float = Field(
        ..., description="SBOM completeness score (0-100)"
    )
    recommendations: List[str] = Field(
        default_factory=list, description="Analysis recommendations"
    )


class PackageInfo(BaseModel):
    """Detailed package information for CLI output."""

    name: str = Field(..., description="Package name")
    version: Optional[str] = Field(None, description="Package version")
    license: Optional[str] = Field(None, description="Primary license")
    description: Optional[str] = Field(None, description="Package description")
    dependencies: List[str] = Field(
        default_factory=list, description="Direct dependencies"
    )
    vulnerabilities: List[str] = Field(
        default_factory=list, description="Known vulnerabilities"
    )
    supplier: Optional[str] = Field(None, description="Package supplier")
    homepage: Optional[str] = Field(None, description="Package homepage")


class DependencyTree(BaseModel):
    """Dependency tree structure for visualization."""

    root_packages: List[str] = Field(
        default_factory=list, description="Root packages (no dependencies)"
    )
    tree_structure: Dict[str, List[str]] = Field(
        default_factory=dict, description="Dependency tree structure"
    )
    depth_analysis: Dict[str, int] = Field(
        default_factory=dict, description="Depth of each package"
    )
    circular_dependencies: List[List[str]] = Field(
        default_factory=list, description="Circular dependency chains"
    )
    total_dependencies: int = Field(..., description="Total number of dependencies")
    max_depth: int = Field(..., description="Maximum dependency depth")
