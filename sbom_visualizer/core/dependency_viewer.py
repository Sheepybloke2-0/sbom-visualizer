"""
Dependency viewer for SBOM Visualizer.

Provides functionality to analyze and visualize dependency relationships.
"""

import logging
from collections import defaultdict
from typing import Dict, List

from ..models.sbom_models import DependencyTree, SBOMData

logger = logging.getLogger(__name__)


class DependencyViewer:
    """Viewer for analyzing dependency relationships in SBOM data."""

    def __init__(self):
        """Initialize the dependency viewer."""
        pass

    def build_dependency_tree(self, sbom_data: SBOMData) -> DependencyTree:
        """Build a dependency tree from SBOM data."""
        if not sbom_data.packages:
            return DependencyTree(
                tree_structure={},
                root_packages=[],
                depth_analysis={},
                circular_dependencies=[],
            )

        # Build dependency graph
        dependency_graph = defaultdict(list)
        reverse_graph = defaultdict(list)
        package_map = {}

        for package in sbom_data.packages:
            package_map[package.name] = package
            for dep in package.dependencies:
                dependency_graph[package.name].append(dep.package_name)
                reverse_graph[dep.package_name].append(package.name)

        # Find root packages (packages with no dependencies)
        root_packages = [
            pkg.name for pkg in sbom_data.packages if not dependency_graph[pkg.name]
        ]

        # Calculate depth for each package
        depth_analysis = {}
        for package in sbom_data.packages:
            depth = self._calculate_package_depth(package.name, dependency_graph)
            depth_analysis[package.name] = depth

        # Detect circular dependencies
        circular_dependencies = self._detect_circular_dependencies(dependency_graph)

        # Build tree structure
        tree_structure = {}
        for package in sbom_data.packages:
            tree_structure[package.name] = {
                "dependencies": dependency_graph[package.name],
                "dependents": reverse_graph[package.name],
                "depth": depth_analysis[package.name],
            }

        return DependencyTree(
            tree_structure=tree_structure,
            root_packages=root_packages,
            depth_analysis=depth_analysis,
            circular_dependencies=circular_dependencies,
        )

    def _calculate_package_depth(
        self, package_name: str, dependency_graph: Dict[str, List[str]]
    ) -> int:
        """Calculate the maximum depth of a package in the dependency tree."""
        visited = set()

        def dfs(node: str, depth: int) -> int:
            if node in visited:
                return depth
            visited.add(node)

            max_depth = depth
            for dep in dependency_graph.get(node, []):
                max_depth = max(max_depth, dfs(dep, depth + 1))

            return max_depth

        return dfs(package_name, 0)

    def _detect_circular_dependencies(
        self, dependency_graph: Dict[str, List[str]]
    ) -> List[List[str]]:
        """Detect circular dependencies in the dependency graph."""
        circular_deps = []
        visited = set()
        rec_stack = set()

        def dfs(node: str, path: List[str]):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in dependency_graph.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    circular_deps.append(cycle)

            rec_stack.remove(node)
            path.pop()

        for node in dependency_graph:
            if node not in visited:
                dfs(node, [])

        return circular_deps

    def find_root_packages(self, sbom_data: SBOMData) -> List[str]:
        """Find root packages (packages with no dependencies)."""
        if not sbom_data.packages:
            return []

        dependency_graph = defaultdict(list)
        for package in sbom_data.packages:
            for dep in package.dependencies:
                dependency_graph[package.name].append(dep.package_name)

        root_packages = [
            pkg.name for pkg in sbom_data.packages if not dependency_graph[pkg.name]
        ]

        return root_packages

    def calculate_max_depth(self, sbom_data: SBOMData) -> int:
        """Calculate the maximum depth of the dependency tree."""
        if not sbom_data.packages:
            return 0

        dependency_graph = defaultdict(list)
        for package in sbom_data.packages:
            for dep in package.dependencies:
                dependency_graph[package.name].append(dep.package_name)

        max_depth = 0
        for package in sbom_data.packages:
            depth = self._calculate_package_depth(package.name, dependency_graph)
            max_depth = max(max_depth, depth)

        return max_depth

    def format_tree_for_cli(self, dependency_tree: DependencyTree) -> str:
        """Format dependency tree for CLI output."""
        if not dependency_tree.tree_structure:
            return "No dependencies found."

        output = []
        output.append("Dependency Tree:")
        output.append("=" * 50)

        # Sort packages by depth
        sorted_packages = sorted(
            dependency_tree.tree_structure.items(),
            key=lambda x: dependency_tree.depth_analysis.get(x[0], 0),
        )

        for package_name, package_info in sorted_packages:
            depth = package_info["depth"]
            indent = "  " * depth
            output.append(f"{indent}📦 {package_name}")

            # Show dependencies
            for dep in package_info["dependencies"]:
                dep_indent = "  " * (depth + 1)
                output.append(f"{dep_indent}└── {dep}")

        # Show circular dependencies if any
        if dependency_tree.circular_dependencies:
            output.append("\n⚠️  Circular Dependencies Detected:")
            for cycle in dependency_tree.circular_dependencies:
                output.append(f"   {' -> '.join(cycle)}")

        return "\n".join(output)
