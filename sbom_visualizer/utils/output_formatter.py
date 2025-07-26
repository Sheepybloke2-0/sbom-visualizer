"""
Output formatter for different output formats.

Supports text, JSON, markdown, and HTML output with modern styling.
"""

import json
from typing import Any, Dict, Union

from ..models.sbom_models import AnalysisResult, DependencyTree, PackageInfo


class OutputFormatter:
    """Formats analysis results for different output types."""
    
    def format(self, data: Union[AnalysisResult, DependencyTree, PackageInfo], 
               output_type: str) -> str:
        """
        Format data for the specified output type.
        
        Args:
            data: Data to format
            output_type: Type of output (text, json, markdown, html)
            
        Returns:
            Formatted output string
        """
        if output_type.lower() == 'text':
            return self._format_text(data)
        elif output_type.lower() == 'json':
            return self._format_json(data)
        elif output_type.lower() == 'markdown':
            return self._format_markdown(data)
        elif output_type.lower() == 'html':
            return self._format_html(data)
        else:
            raise ValueError(f"Unsupported output type: {output_type}")
    
    def _format_text(self, data: Union[AnalysisResult, DependencyTree, PackageInfo]) -> str:
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
            for license_name, count in sorted(analysis.license_distribution.items(), 
                                           key=lambda x: x[1], reverse=True)[:10]:
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
            output.append(f"  ⚠️  Circular dependencies: {len(tree.circular_dependencies)}")
        
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
    
    def _format_json(self, data: Union[AnalysisResult, DependencyTree, PackageInfo]) -> str:
        """Format data as JSON."""
        return json.dumps(data.dict(), indent=2)
    
    def _format_markdown(self, data: Union[AnalysisResult, DependencyTree, PackageInfo]) -> str:
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
            for license_name, count in sorted(analysis.license_distribution.items(), 
                                           key=lambda x: x[1], reverse=True)[:10]:
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
            output.append(f"- **Circular dependencies**: {len(tree.circular_dependencies)}")
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
    
    def _format_html(self, data: Union[AnalysisResult, DependencyTree, PackageInfo]) -> str:
        """Format data as HTML with modern styling."""
        if isinstance(data, AnalysisResult):
            return self._format_analysis_html(data)
        elif isinstance(data, DependencyTree):
            return self._format_tree_html(data)
        elif isinstance(data, PackageInfo):
            return self._format_package_html(data)
        else:
            return f"<html><body><pre>{str(data)}</pre></body></html>"
    
    def _format_analysis_html(self, analysis: AnalysisResult) -> str:
        """Format analysis result as HTML."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .content {{
            padding: 30px;
        }}
        .stat {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #667eea;
        }}
        .stat h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        .license-item {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .recommendation {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }}
        .vulnerability {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 10px;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 SBOM Analysis Report</h1>
        </div>
        <div class="content">
            <div class="stat">
                <h3>📦 Summary</h3>
                <p><strong>Total Packages:</strong> {analysis.total_packages}</p>
                <p><strong>Unique Licenses:</strong> {len(analysis.unique_licenses)}</p>
                <p><strong>Completeness Score:</strong> {analysis.completeness_score:.1f}%</p>
            </div>
            
            {self._format_license_distribution_html(analysis)}
            {self._format_vulnerability_summary_html(analysis)}
            {self._format_recommendations_html(analysis)}
        </div>
    </div>
</body>
</html>
"""
    
    def _format_license_distribution_html(self, analysis: AnalysisResult) -> str:
        """Format license distribution as HTML."""
        if not analysis.license_distribution:
            return ""
        
        items = []
        for license_name, count in sorted(analysis.license_distribution.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
            items.append(f'<div class="license-item"><span>{license_name}</span><span>{count}</span></div>')
        
        return f"""
            <div class="stat">
                <h3>📜 License Distribution</h3>
                {''.join(items)}
            </div>
        """
    
    def _format_vulnerability_summary_html(self, analysis: AnalysisResult) -> str:
        """Format vulnerability summary as HTML."""
        if not analysis.vulnerability_summary:
            return ""
        
        items = []
        for severity, count in analysis.vulnerability_summary.items():
            items.append(f'<div class="vulnerability"><strong>{severity}:</strong> {count}</div>')
        
        return f"""
            <div class="stat">
                <h3>⚠️ Vulnerability Summary</h3>
                {''.join(items)}
            </div>
        """
    
    def _format_recommendations_html(self, analysis: AnalysisResult) -> str:
        """Format recommendations as HTML."""
        if not analysis.recommendations:
            return ""
        
        items = []
        for i, rec in enumerate(analysis.recommendations, 1):
            items.append(f'<div class="recommendation">{i}. {rec}</div>')
        
        return f"""
            <div class="stat">
                <h3>💡 Recommendations</h3>
                {''.join(items)}
            </div>
        """
    
    def _format_tree_html(self, tree: DependencyTree) -> str:
        """Format dependency tree as HTML."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Tree</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .content {{
            padding: 30px;
        }}
        .stat {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #667eea;
        }}
        .dependency-item {{
            padding: 5px 0;
            border-left: 2px solid #eee;
            margin-left: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌳 Dependency Tree</h1>
        </div>
        <div class="content">
            <div class="stat">
                <h3>📊 Statistics</h3>
                <p><strong>Total dependencies:</strong> {tree.total_dependencies}</p>
                <p><strong>Maximum depth:</strong> {tree.max_depth}</p>
                <p><strong>Root packages:</strong> {len(tree.root_packages)}</p>
                {f'<p><strong>Circular dependencies:</strong> {len(tree.circular_dependencies)}</p>' if tree.circular_dependencies else ''}
            </div>
            
            <div class="stat">
                <h3>📦 Root Packages</h3>
                {''.join(f'<div class="dependency-item">└── {root}</div>' for root in tree.root_packages)}
            </div>
            
            <div class="stat">
                <h3>📋 Dependency Structure</h3>
                {''.join(f'<div><strong>{package}</strong>{''.join(f"<div class='dependency-item'>├── {dep}</div>" for dep in deps[:5])}{f"<div class='dependency-item'>└── ... and {len(deps) - 5} more</div>" if len(deps) > 5 else ""}</div>' for package, deps in list(tree.tree_structure.items())[:10])}
            </div>
        </div>
    </div>
</body>
</html>
"""
    
    def _format_package_html(self, package: PackageInfo) -> str:
        """Format package info as HTML."""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Package: {package.name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .content {{
            padding: 30px;
        }}
        .info-item {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
            border-left: 4px solid #667eea;
        }}
        .dependency-item {{
            padding: 5px 0;
            border-left: 2px solid #eee;
            margin-left: 20px;
        }}
        .vulnerability-item {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 10px;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📦 Package: {package.name}</h1>
        </div>
        <div class="content">
            <div class="info-item">
                <h3>📋 Basic Information</h3>
                {f'<p><strong>Version:</strong> {package.version}</p>' if package.version else ''}
                {f'<p><strong>License:</strong> {package.license}</p>' if package.license else ''}
                {f'<p><strong>Supplier:</strong> {package.supplier}</p>' if package.supplier else ''}
                {f'<p><strong>Homepage:</strong> <a href="{package.homepage}">{package.homepage}</a></p>' if package.homepage else ''}
                {f'<p><strong>Description:</strong> {package.description}</p>' if package.description else ''}
            </div>
            
            {f'<div class="info-item"><h3>🔗 Dependencies ({len(package.dependencies)})</h3>{''.join(f"<div class='dependency-item'>- {dep}</div>" for dep in package.dependencies[:10])}{f"<div class='dependency-item'>... and {len(package.dependencies) - 10} more</div>" if len(package.dependencies) > 10 else ""}</div>' if package.dependencies else ''}
            
            {f'<div class="info-item"><h3>⚠️ Vulnerabilities ({len(package.vulnerabilities)})</h3>{''.join(f"<div class='vulnerability-item'>{vuln}</div>" for vuln in package.vulnerabilities[:5])}{f"<div class='vulnerability-item'>... and {len(package.vulnerabilities) - 5} more</div>" if len(package.vulnerabilities) > 5 else ""}</div>' if package.vulnerabilities else ''}
        </div>
    </div>
</body>
</html>
""" 