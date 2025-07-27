"""
Verification service for SBOM validation.

Provides specialized verification operations and compliance checking.
"""

import logging
from typing import Any, Dict, List

from ..core.verifier import SBOMVerifier
from ..exceptions import SBOMVerificationError
from ..models.sbom_models import SBOMData, VerificationResult

logger = logging.getLogger(__name__)


class VerificationService:
    """Service for SBOM verification operations."""

    def __init__(self, verifier: SBOMVerifier = None):
        """Initialize the verification service."""
        self.verifier = verifier or SBOMVerifier()

    def verify_sbom(self, sbom_data: SBOMData) -> VerificationResult:
        """
        Verify SBOM data for compliance and completeness.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Verification result with issues and warnings
        """
        try:
            logger.info(f"Starting verification of SBOM: {sbom_data.document_name}")
            result = self.verifier.verify(sbom_data)
            logger.info(f"Verification completed: {len(result.issues)} issues found")
            return result

        except Exception as e:
            raise SBOMVerificationError(f"Verification failed: {e}")

    def get_verification_summary(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get a summary of SBOM verification.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Verification summary dictionary
        """
        try:
            verification = self.verify_sbom(sbom_data)

            summary = {
                "is_valid": verification.is_valid,
                "total_issues": len(verification.issues),
                "total_warnings": len(verification.warnings),
                "compliance_score": verification.compliance_score,
                "format_compliance": verification.format_compliance_score,
                "license_compliance": verification.license_compliance_score,
                "dependency_completeness": verification.dependency_completeness_score,
                "package_completeness": verification.package_completeness_score,
                "metadata_score": verification.metadata_score,
                "overall_score": verification.overall_score,
            }

            logger.info(
                f"Verification summary generated: {summary['total_issues']} issues"
            )
            return summary

        except Exception as e:
            raise SBOMVerificationError(f"Failed to generate verification summary: {e}")

    def get_compliance_report(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get detailed compliance report.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Compliance report dictionary
        """
        try:
            verification = self.verify_sbom(sbom_data)

            compliance_report = {
                "overall_compliance": verification.is_valid,
                "format_compliance": {
                    "score": verification.format_compliance_score,
                    "issues": [
                        issue
                        for issue in verification.issues
                        if "format" in issue.lower()
                    ],
                },
                "license_compliance": {
                    "score": verification.license_compliance_score,
                    "issues": [
                        issue
                        for issue in verification.issues
                        if "license" in issue.lower()
                    ],
                },
                "dependency_completeness": {
                    "score": verification.dependency_completeness_score,
                    "issues": [
                        issue
                        for issue in verification.issues
                        if "dependency" in issue.lower()
                    ],
                },
                "package_completeness": {
                    "score": verification.package_completeness_score,
                    "issues": [
                        issue
                        for issue in verification.issues
                        if "package" in issue.lower()
                    ],
                },
                "metadata_quality": {
                    "score": verification.metadata_score,
                    "issues": [
                        issue
                        for issue in verification.issues
                        if "metadata" in issue.lower()
                    ],
                },
                "critical_issues": [
                    issue
                    for issue in verification.issues
                    if "critical" in issue.lower()
                ],
                "warnings": verification.warnings,
            }

            logger.info(
                f"Compliance report generated: {compliance_report['overall_compliance']}"
            )
            return compliance_report

        except Exception as e:
            raise SBOMVerificationError(f"Failed to generate compliance report: {e}")

    def get_validation_details(self, sbom_data: SBOMData) -> Dict[str, Any]:
        """
        Get detailed validation information.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Validation details dictionary
        """
        try:
            verification = self.verify_sbom(sbom_data)

            validation_details = {
                "validation_status": "PASS" if verification.is_valid else "FAIL",
                "total_checks": len(verification.issues) + len(verification.warnings),
                "passed_checks": len(
                    [issue for issue in verification.issues if "PASS" in issue]
                ),
                "failed_checks": len(
                    [issue for issue in verification.issues if "FAIL" in issue]
                ),
                "warnings": len(verification.warnings),
                "scores": {
                    "format": verification.format_compliance_score,
                    "license": verification.license_compliance_score,
                    "dependency": verification.dependency_completeness_score,
                    "package": verification.package_completeness_score,
                    "metadata": verification.metadata_score,
                    "overall": verification.overall_score,
                },
                "recommendations": self._generate_validation_recommendations(
                    verification
                ),
            }

            logger.info(
                f"Validation details generated: {validation_details['validation_status']}"
            )
            return validation_details

        except Exception as e:
            raise SBOMVerificationError(f"Failed to generate validation details: {e}")

    def _generate_validation_recommendations(
        self, verification: VerificationResult
    ) -> List[str]:
        """
        Generate recommendations based on verification results.

        Args:
            verification: Verification result

        Returns:
            List of recommendations
        """
        recommendations = []

        if not verification.is_valid:
            recommendations.append(
                "SBOM validation failed. Review and fix issues before proceeding."
            )

        if verification.format_compliance_score < 80:
            recommendations.append(
                "Improve format compliance by following SBOM standards."
            )

        if verification.license_compliance_score < 80:
            recommendations.append(
                "Add missing license information to improve compliance."
            )

        if verification.dependency_completeness_score < 80:
            recommendations.append(
                "Add missing dependency information for better completeness."
            )

        if verification.package_completeness_score < 80:
            recommendations.append(
                "Add missing package metadata for better completeness."
            )

        if verification.metadata_score < 80:
            recommendations.append(
                "Improve metadata quality by adding required fields."
            )

        if len(verification.warnings) > 0:
            recommendations.append(
                f"Address {len(verification.warnings)} warnings to improve quality."
            )

        return recommendations
