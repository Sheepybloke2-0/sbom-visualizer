# SBOM Visualizer

A web app to help visualize and understand the contents of an SBOM. The goal is to be an AI powered SBOM analysis and visualization tool to allow for users to easily parse and understand SBOMs. The plan for this is to be the Notebook LM version of SBOM analysis.

Supports the standard, machine readable SBOM formats like SPDX and CycloneDX. Type is automatically detected by the program.

Supported SBOM types are:
- SPDX 3.0
- CylconeDX 1.5
- SWID

Includes AI integration with Claude to check for CVEs, potential license issues, and provides a chat for users to parse and analyze SBOMs.

Leverages a Python backend with a GraphQL schema.

SOPS, .netrc, and environment variables are used for storing API keys.

## CLI

```
sbom-analyzer [--options] command args

options:
    --verbose : increase the log level to DEBUG.
    --quiet : Decrease the log level to WARN.

commands:
    analyze [file] : Analyze an SBOM file and generate a detailed report. Default report is human-readable text formatted for a CLI.
        Options:
            -o, --output [filename] : specify the output filename
            -t, --type [text, json, markdown, html] : output type. Text is human readable text designed for CLIs. JSON is for machine processing, while markdown and HTML are for external reporting.
    verify [file] - Verify an SBOM file. Reports any potential issues with the SBOM format, license issues depenancy completeness.
    dep [file] - Show the dependency tree for an SBOM. Default output is a human-readable tree formatted for a CLI. Tree shows package name and version and is interactive for larger SBOMs. Detailed information should be found with `check-pkg`.
        Options:
            -o, --output [filename] : specify the output filename
            -t, --type [text, json, markdown, html] : output type. Text is human readable text designed for CLIs. JSON is for machine processing, while markdown and HTML are for external reporting.
    check-pkg [file] [package-name] - Get the detailed information about a package in the SBOM. Also supports fuzzy matching for the package name.
    scan [file] - Scan the SBOM for any potential CVEs. Checks packages against the latest list from CVE.org. Default is human-readable text formatted for a CLI. This will be implemented as part of Stage 4.
        Options:
            -o, --output [filename] : specify the output filename
            -t, --type [text, json, markdown, html] : output type. Text is human readable text designed for CLIs. JSON is for machine processing, while markdown and HTML are for external reporting.
```
