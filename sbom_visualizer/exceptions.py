"""
Custom exceptions for SBOM Visualizer.

Provides specific exception types for different error scenarios.
"""


class SBOMError(Exception):
    """Base exception for SBOM operations."""

    def __init__(self, message: str, details: str = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class SBOMParseError(SBOMError):
    """Error parsing SBOM file."""

    pass


class SBOMValidationError(SBOMError):
    """Error validating SBOM data."""

    pass


class SBOMFormatError(SBOMError):
    """Error with SBOM format detection or unsupported format."""

    pass


class SBOMFileError(SBOMError):
    """Error with file operations (not found, permissions, etc.)."""

    pass


class SBOMAnalysisError(SBOMError):
    """Error during SBOM analysis."""

    pass


class SBOMVerificationError(SBOMError):
    """Error during SBOM verification."""

    pass


class SBOMOutputError(SBOMError):
    """Error during output formatting."""

    pass


class SBOMConfigurationError(SBOMError):
    """Error with application configuration."""

    pass
