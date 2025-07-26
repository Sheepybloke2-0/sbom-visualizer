"""
Dependency Viewer for SBOM dependency tree visualization.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Set

from ..models.sbom_models import SBOMData, DependencyTree


logger = logging.getLogger(__name__)


class DependencyViewer:
    """Generates dependency trees and handles interactive visualization."""

    def generate_tree(self, sbom_data: SBOMData) -> DependencyTree:
        """
        Generate dependency tree from SBOM data.

        Args:
            sbom_data: Parsed SBOM data

        Returns:
            Dependency tree structure
        """
        logger.info(f"Generating dependency tree for {sbom_data.document_name}")

        # Build dependency graph
        dependency_graph = self._build_dependency_graph(sbom_data)

        # Find root packages (no incoming dependencies)
        root_packages = self._find_root_packages(sbom_data, dependency_graph)

        # Calculate depth for each package
        depth_analysis = self._calculate_depth_analysis(sbom_data, dependency_graph)

        # Find circular dependencies
        circular_dependencies = self._find_circular_dependencies(dependency_graph)

        # Calculate statistics
        total_dependencies = sum(len(deps) for deps in dependency_graph.values())
        max_depth = max(depth_analysis.values()) if depth_analysis else 0

        return DependencyTree(
            root_packages=root_packages,
            tree_structure=dependency_graph,
            depth_analysis=depth_analysis,
            circular_dependencies=circular_dependencies,
            total_dependencies=total_dependencies,
            max_depth=max_depth,
        )

    def _build_dependency_graph(self, sbom_data: SBOMData) -> Dict[str, List[str]]:
        """Build dependency graph from SBOM data."""
        dependency_graph = defaultdict(list)

        # Create package ID to name mapping
        package_map = {package.id: package.name for package in sbom_data.packages}

        # Build graph from package dependencies
        for package in sbom_data.packages:
            for dep in package.dependencies:
                dependency_graph[package.name].append(dep.package_name)

        # Add relationships from SBOM relationships
        for rel in sbom_data.relationships:
            if "dependsOn" in rel:
                # This is a simplified approach - in reality you'd need to map IDs to names
                pass

        return dict(dependency_graph)

    def _find_root_packages(
        self, sbom_data: SBOMData, dependency_graph: Dict[str, List[str]]
    ) -> List[str]:
        """Find packages with no incoming dependencies."""
        all_dependents = set()
        for deps in dependency_graph.values():
            all_dependents.update(deps)

        root_packages = []
        for package in sbom_data.packages:
            if package.name not in all_dependents:
                root_packages.append(package.name)

        return root_packages

    def _calculate_depth_analysis(
        self, sbom_data: SBOMData, dependency_graph: Dict[str, List[str]]
    ) -> Dict[str, int]:
        """Calculate depth for each package in the dependency tree."""
        depth_analysis = {}
        visited = set()

        def calculate_depth(package_name: str, depth: int) -> int:
            if package_name in visited:
                return depth

            visited.add(package_name)
            max_depth = depth

            for dep in dependency_graph.get(package_name, []):
                dep_depth = calculate_depth(dep, depth + 1)
                max_depth = max(max_depth, dep_depth)

            depth_analysis[package_name] = max_depth
            return max_depth

        # Calculate depth for all packages
        for package in sbom_data.packages:
            if package.name not in visited:
                calculate_depth(package.name, 0)

        return depth_analysis

    def _find_circular_dependencies(
        self, dependency_graph: Dict[str, List[str]]
    ) -> List[List[str]]:
        """Find circular dependencies in the dependency graph."""
        circular_deps = []
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]) -> None:
            if node in rec_stack:
                # Found a cycle
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                circular_deps.append(cycle)
                return

            if node in visited:
                return

            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in dependency_graph.get(node, []):
                dfs(neighbor, path.copy())

            rec_stack.remove(node)

        for node in dependency_graph:
            if node not in visited:
                dfs(node, [])

        return circular_deps

    def format_tree_for_cli(self, tree: DependencyTree, max_depth: int = 3) -> str:
        """
        Format dependency tree for CLI output.

        Args:
            tree: Dependency tree
            max_depth: Maximum depth to display

        Returns:
            Formatted tree string
        """
        output = []
        output.append("🌳 Dependency Tree")
        output.append("=" * 50)

        # Show root packages
        if tree.root_packages:
            output.append("📦 Root Packages:")
            for root in tree.root_packages:
                output.append(f"  └── {root}")

        # Show tree structure (limited depth)
        output.append("\n📋 Dependency Structure:")
        for package, deps in tree.tree_structure.items():
            if deps:
                output.append(f"  {package}")
                for i, dep in enumerate(deps[:max_depth]):
                    prefix = "  └── " if i == len(deps) - 1 else "  ├── "
                    output.append(f"{prefix}{dep}")
                if len(deps) > max_depth:
                    output.append(f"  └── ... and {len(deps) - max_depth} more")

        # Show statistics
        output.append(f"\n📊 Statistics:")
        output.append(f"  Total dependencies: {tree.total_dependencies}")
        output.append(f"  Maximum depth: {tree.max_depth}")
        output.append(f"  Root packages: {len(tree.root_packages)}")

        if tree.circular_dependencies:
            output.append(
                f"  ⚠️  Circular dependencies: {len(tree.circular_dependencies)}"
            )

        return "\n".join(output)
