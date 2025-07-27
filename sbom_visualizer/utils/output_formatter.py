"""
Output formatter for SBOM Visualizer.

Provides functionality to format analysis results in various output formats.
"""

import logging
from typing import Any, Union
import json

from ..models.sbom_models import AnalysisResult, DependencyTree, PackageInfo


class OutputFormatter:
    """Formats analysis results for different output types."""

    def format(
        self, data: Union[AnalysisResult, DependencyTree, PackageInfo], output_type: str
    ) -> str:
        """
        Format data for the specified output type.

        Args:
            data: Data to format
            output_type: Type of output (text, json, markdown, html)

        Returns:
            Formatted output string
        """
        if output_type.lower() == "text":
            return self._format_text(data)
        elif output_type.lower() == "json":
            return self._format_json(data)
        elif output_type.lower() == "markdown":
            return self._format_markdown(data)
        elif output_type.lower() == "html":
            return self._format_html(data)
        else:
            raise ValueError(f"Unsupported output type: {output_type}")

    def _format_text(
        self, data: Union[AnalysisResult, DependencyTree, PackageInfo]
    ) -> str:
        """Format data as human-readable text."""
        if isinstance(data, AnalysisResult):
            return self._format_analysis_text(data)
        elif isinstance(data, DependencyTree):
            return self._format_tree_text(data)
        elif isinstance(data, PackageInfo):
            return self._format_package_text(data)
        else:
            return str(data)

    def _format_analysis_text(self, analysis: AnalysisResult) -> str:
        """Format analysis result as text."""
        output = []
        output.append("📊 SBOM Analysis Report")
        output.append("=" * 50)

        # Basic statistics
        output.append(f"📦 Total Packages: {analysis.total_packages}")
        output.append(f"📋 Unique Licenses: {len(analysis.unique_licenses)}")
        output.append(f"🎯 Completeness Score: {analysis.completeness_score:.1f}%")

        # License distribution
        if analysis.license_distribution:
            output.append("\n📜 License Distribution:")
            for license_name, count in sorted(
                analysis.license_distribution.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                output.append(f"  {license_name}: {count}")

        # Vulnerability summary
        if analysis.vulnerability_summary:
            output.append("\n⚠️  Vulnerability Summary:")
            for severity, count in analysis.vulnerability_summary.items():
                output.append(f"  {severity}: {count}")

        # Recommendations
        if analysis.recommendations:
            output.append("\n💡 Recommendations:")
            for i, rec in enumerate(analysis.recommendations, 1):
                output.append(f"  {i}. {rec}")

        return "\n".join(output)

    def _format_tree_text(self, tree: DependencyTree) -> str:
        """Format dependency tree as text."""
        output = []
        output.append("🌳 Dependency Tree")
        output.append("=" * 50)

        # Root packages
        if tree.root_packages:
            output.append("📦 Root Packages:")
            for root in tree.root_packages:
                output.append(f"  └── {root}")

        # Tree structure (limited)
        output.append("\n📋 Dependency Structure:")
        for package, deps in list(tree.tree_structure.items())[:10]:
            if deps:
                output.append(f"  {package}")
                for i, dep in enumerate(deps[:5]):
                    prefix = "  └── " if i == len(deps) - 1 else "  ├── "
                    output.append(f"{prefix}{dep}")
                if len(deps) > 5:
                    output.append(f"  └── ... and {len(deps) - 5} more")

        # Statistics
        output.append(f"\n📊 Statistics:")
        output.append(f"  Total dependencies: {tree.total_dependencies}")
        output.append(f"  Maximum depth: {tree.max_depth}")
        output.append(f"  Root packages: {len(tree.root_packages)}")

        if tree.circular_dependencies:
            output.append(
                f"  ⚠️  Circular dependencies: {len(tree.circular_dependencies)}"
            )

        return "\n".join(output)

    def _format_package_text(self, package: PackageInfo) -> str:
        """Format package info as text."""
        output = []
        output.append(f"📦 Package: {package.name}")
        output.append("=" * 30)

        if package.version:
            output.append(f"📋 Version: {package.version}")

        if package.license:
            output.append(f"📜 License: {package.license}")

        if package.description:
            output.append(f"📝 Description: {package.description}")

        if package.supplier:
            output.append(f"🏢 Supplier: {package.supplier}")

        if package.homepage:
            output.append(f"🌐 Homepage: {package.homepage}")

        if package.dependencies:
            output.append(f"🔗 Dependencies ({len(package.dependencies)}):")
            for dep in package.dependencies[:5]:
                output.append(f"  - {dep}")
            if len(package.dependencies) > 5:
                output.append(f"  ... and {len(package.dependencies) - 5} more")

        if package.vulnerabilities:
            output.append(f"⚠️  Vulnerabilities ({len(package.vulnerabilities)}):")
            for vuln in package.vulnerabilities[:3]:
                output.append(f"  - {vuln}")
            if len(package.vulnerabilities) > 3:
                output.append(f"  ... and {len(package.vulnerabilities) - 3} more")

        return "\n".join(output)

    def _format_json(self, data: Any) -> str:
        """Format data as JSON."""
        return json.dumps(data.model_dump(), indent=2)

    def _format_markdown(
        self, data: Union[AnalysisResult, DependencyTree, PackageInfo]
    ) -> str:
        """Format data as markdown."""
        if isinstance(data, AnalysisResult):
            return self._format_analysis_markdown(data)
        elif isinstance(data, DependencyTree):
            return self._format_tree_markdown(data)
        elif isinstance(data, PackageInfo):
            return self._format_package_markdown(data)
        else:
            return str(data)

    def _format_analysis_markdown(self, analysis: AnalysisResult) -> str:
        """Format analysis result as markdown."""
        output = []
        output.append("# SBOM Analysis Report")
        output.append("")

        # Basic statistics
        output.append("## Summary")
        output.append("")
        output.append(f"- **Total Packages**: {analysis.total_packages}")
        output.append(f"- **Unique Licenses**: {len(analysis.unique_licenses)}")
        output.append(f"- **Completeness Score**: {analysis.completeness_score:.1f}%")
        output.append("")

        # License distribution
        if analysis.license_distribution:
            output.append("## License Distribution")
            output.append("")
            for license_name, count in sorted(
                analysis.license_distribution.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                output.append(f"- **{license_name}**: {count}")
            output.append("")

        # Vulnerability summary
        if analysis.vulnerability_summary:
            output.append("## Vulnerability Summary")
            output.append("")
            for severity, count in analysis.vulnerability_summary.items():
                output.append(f"- **{severity}**: {count}")
            output.append("")

        # Recommendations
        if analysis.recommendations:
            output.append("## Recommendations")
            output.append("")
            for i, rec in enumerate(analysis.recommendations, 1):
                output.append(f"{i}. {rec}")
            output.append("")

        return "\n".join(output)

    def _format_tree_markdown(self, tree: DependencyTree) -> str:
        """Format dependency tree as markdown."""
        output = []
        output.append("# Dependency Tree")
        output.append("")

        # Root packages
        if tree.root_packages:
            output.append("## Root Packages")
            output.append("")
            for root in tree.root_packages:
                output.append(f"- {root}")
            output.append("")

        # Tree structure
        output.append("## Dependency Structure")
        output.append("")
        for package, deps in list(tree.tree_structure.items())[:10]:
            if deps:
                output.append(f"### {package}")
                for dep in deps[:5]:
                    output.append(f"- {dep}")
                if len(deps) > 5:
                    output.append(f"- ... and {len(deps) - 5} more")
                output.append("")

        # Statistics
        output.append("## Statistics")
        output.append("")
        output.append(f"- **Total dependencies**: {tree.total_dependencies}")
        output.append(f"- **Maximum depth**: {tree.max_depth}")
        output.append(f"- **Root packages**: {len(tree.root_packages)}")
        if tree.circular_dependencies:
            output.append(
                f"- **Circular dependencies**: {len(tree.circular_dependencies)}"
            )
        output.append("")

        return "\n".join(output)

    def _format_package_markdown(self, package: PackageInfo) -> str:
        """Format package info as markdown."""
        output = []
        output.append(f"# Package: {package.name}")
        output.append("")

        if package.version:
            output.append(f"**Version**: {package.version}")
            output.append("")

        if package.license:
            output.append(f"**License**: {package.license}")
            output.append("")

        if package.description:
            output.append(f"**Description**: {package.description}")
            output.append("")

        if package.supplier:
            output.append(f"**Supplier**: {package.supplier}")
            output.append("")

        if package.homepage:
            output.append(f"**Homepage**: {package.homepage}")
            output.append("")

        if package.dependencies:
            output.append("## Dependencies")
            output.append("")
            for dep in package.dependencies[:10]:
                output.append(f"- {dep}")
            if len(package.dependencies) > 10:
                output.append(f"- ... and {len(package.dependencies) - 10} more")
            output.append("")

        if package.vulnerabilities:
            output.append("## Vulnerabilities")
            output.append("")
            for vuln in package.vulnerabilities[:5]:
                output.append(f"- {vuln}")
            if len(package.vulnerabilities) > 5:
                output.append(f"- ... and {len(package.vulnerabilities) - 5} more")
            output.append("")

        return "\n".join(output)

    def _format_html(self, result: Any) -> str:
        """Format result as HTML with modern styling."""
        if result is None:
            return "<p>No data available</p>"

        # Start HTML document
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SBOM Analysis Results</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }
                .content {
                    padding: 30px;
                }
                .section {
                    margin-bottom: 30px;
                    padding: 20px;
                    border-radius: 8px;
                    background: #f8f9fa;
                    border-left: 4px solid #667eea;
                }
                .section h2 {
                    margin-top: 0;
                    color: #333;
                    font-size: 1.5em;
                }
                .metric {
                    display: inline-block;
                    margin: 10px;
                    padding: 15px 20px;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                    min-width: 120px;
                }
                .metric-value {
                    font-size: 2em;
                    font-weight: bold;
                    color: #667eea;
                }
                .metric-label {
                    color: #666;
                    font-size: 0.9em;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                .list-item {
                    padding: 8px 0;
                    border-bottom: 1px solid #eee;
                }
                .list-item:last-child {
                    border-bottom: none;
                }
                .recommendation {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    border-radius: 6px;
                    padding: 15px;
                    margin: 10px 0;
                }
                .vulnerability {
                    background: #f8d7da;
                    border: 1px solid #f5c6cb;
                    border-radius: 6px;
                    padding: 10px;
                    margin: 5px 0;
                }
                .license {
                    background: #d1ecf1;
                    border: 1px solid #bee5eb;
                    border-radius: 6px;
                    padding: 10px;
                    margin: 5px 0;
                }
                @media (max-width: 768px) {
                    .container {
                        margin: 10px;
                        border-radius: 8px;
                    }
                    .header {
                        padding: 20px;
                    }
                    .header h1 {
                        font-size: 2em;
                    }
                    .content {
                        padding: 20px;
                    }
                    .metric {
                        display: block;
                        margin: 10px 0;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📊 SBOM Analysis Results</h1>
                </div>
                <div class="content">
        """

        # Add content based on result type
        if hasattr(result, "total_packages"):
            html += f"""
                    <div class="section">
                        <h2>📦 Package Analysis</h2>
                        <div class="metric">
                            <div class="metric-value">{result.total_packages}</div>
                            <div class="metric-label">Total Packages</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">{len(result.unique_licenses)}</div>
                            <div class="metric-label">Unique Licenses</div>
                        </div>
                    </div>
            """

        if hasattr(result, "vulnerability_summary") and result.vulnerability_summary:
            html += """
                    <div class="section">
                        <h2>⚠️ Vulnerability Summary</h2>
            """
            for severity, count in result.vulnerability_summary.items():
                if count > 0:
                    html += f"""
                        <div class="vulnerability">
                            <strong>{severity.title()}:</strong> {count} vulnerabilities
                        </div>
                    """
            html += "</div>"
        else:
            html += """
                    <div class="section">
                        <h2>⚠️ Vulnerability Summary</h2>
                        <div class="vulnerability">
                            <strong>No vulnerabilities found</strong>
                        </div>
                    </div>
            """

        if hasattr(result, "recommendations") and result.recommendations:
            html += """
                    <div class="section">
                        <h2>💡 Recommendations</h2>
            """
            for i, recommendation in enumerate(result.recommendations, 1):
                html += f"""
                        <div class="recommendation">
                            {i}. {recommendation}
                        </div>
                """
            html += "</div>"
        else:
            html += """
                    <div class="section">
                        <h2>💡 Recommendations</h2>
                        <div class="recommendation">
                            <strong>No recommendations available</strong>
                        </div>
                    </div>
            """

        # Close HTML
        html += """
                </div>
            </div>
        </body>
        </html>
        """

        return html
