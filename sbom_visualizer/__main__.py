"""
Main entry point for SBOM Visualizer.

Allows running the package as a module: python -m sbom_visualizer
"""

from .cli import cli

if __name__ == "__main__":
    cli()
