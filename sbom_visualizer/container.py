"""
Dependency injection container for SBOM Visualizer.

Manages component dependencies and provides centralized configuration.
"""

from pathlib import Path

from dependency_injector import containers, providers

from .config import settings
from .core.analyzer import SBOMAnalyzer
from .core.dependency_viewer import DependencyViewer
from .core.package_checker import PackageChecker
from .core.parser import SBOMParser
from .core.verifier import SBOMVerifier
from .services.analysis_service import AnalysisService
from .services.sbom_service import SBOMService
from .services.verification_service import VerificationService
from .utils.output_formatter import OutputFormatter


class Container(containers.DeclarativeContainer):
    """Dependency injection container for SBOM Visualizer."""

    # Configuration
    config = providers.Configuration()
    config.from_dict(
        {
            "app_name": settings.app_name,
            "version": settings.version,
            "debug": settings.debug,
            "api_host": settings.api_host,
            "api_port": settings.api_port,
            "max_file_size": settings.max_file_size,
            "allowed_extensions": settings.allowed_extensions,
        }
    )

    # Core components
    parser = providers.Singleton(SBOMParser)
    analyzer = providers.Singleton(SBOMAnalyzer)
    verifier = providers.Singleton(SBOMVerifier)
    dependency_viewer = providers.Singleton(DependencyViewer)
    package_checker = providers.Singleton(PackageChecker)

    # Services
    sbom_service = providers.Singleton(
        SBOMService,
        parser=parser,
        analyzer=analyzer,
        verifier=verifier,
        dependency_viewer=dependency_viewer,
        package_checker=package_checker,
    )

    analysis_service = providers.Singleton(
        AnalysisService,
        analyzer=analyzer,
        dependency_viewer=dependency_viewer,
    )

    verification_service = providers.Singleton(
        VerificationService,
        verifier=verifier,
    )

    # Utilities
    output_formatter = providers.Singleton(OutputFormatter)


# Global container instance
container = Container()
