# Implementation Plan

## Stage 1: CLI Tool
- [ ] Basic CLI structure
- [ ] SPDX file parsing
- [ ] CycloneDX file parsing
- [ ] SWID file parsing
- [ ] SBOM verification
- [ ] Output report for issues found
- [ ] Command line interface
- [ ] Output generation
- [ ] Dependancy viewer
- [ ] Unit Tests
- [ ] Make the CLI pretty by leveraging animations, colors, and emojis.
- [ ] CLI can be interactive if it makes sense for the command.
- [ ] Checking the processed SBOM's size and breaking it up into smaller pieces to display to the user if too large.
- [ ] Generate example SBOMs from the base ubuntu docker image and from an example application for testing. Create one for each supported type.
- [ ] Notify users of errors with descriptive messages, but not suggestions for fixes
- [ ] Separate message types for malformed SBOM files and valid, incomplete SBOMs.
- [ ] Use CSS styling with a modern, soft, colorful design with for a dark mode for the HTML reports. 

## Stage 2: Viewer Page
- [ ] Web interface setup
- [ ] SBOM data visualization
- [ ] Interactive components
- [ ] File upload handling
- [ ] Use CSS styling with a modern, soft, colorful design with for a dark mode for the HTML reports. 
- [ ] Unit Tests
- [ ] Integration Tests

## Stage 3: Users
- [ ] Provides a user login portal that can be extended to more complex login providers in the future
- [ ] Provides user sessions for uploading and parsing SBOMs and their analysis

## Stage 4: AI Integration
- [ ] AI analysis features
- [ ] Automated insights
- [ ] Notify users about license errors and ask AI for suggestions for fixes
- [ ] Pages for viewing license information and understanding what the license mean
- [ ] Pages for viewing CVE issues and understanding what the issue is and if there are patches
- [ ] Chat interface to help understand the data
- [ ] Keep costs low by limiting the number of tokens used
- [ ] Support for saving the session by storing session information from the AI.
