"""
Setup configuration for SBOM Visualizer.
"""

from setuptools import setup, find_packages

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="sbom-visualizer",
    version="0.1.0",
    author="SBOM Visualizer Team",
    author_email="team@sbom-visualizer.com",
    description="AI-powered SBOM analysis and visualization tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sbom-visualizer/sbom-visualizer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "sbom-analyzer=sbom_visualizer.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
