# Tech Stack

## Backend
- Python 3.12+
    - Required for better compatability with the tooling
- FastAPI for webAI
- GrpahQL for the API schema
- Strawberry for the GraphQL API Python library
- Click for the CLI
- spdx-tools for parsing SPDX SBOMs
- cyclonedx-python-lib for parsing CycloneDX SBOMs
- SQLAchemy for the database schema
- MongoDB for the database
- Contianerized database
- Contianerized application
- SOPS for simple secret management
- Claude Haiku 3.5 for AI model
- Claude API for AI insites
- SPDX file format for uploads to the AI platform
- pynacl used for password management
- mermaid for graph generation

## Frontend
- React/TypeScript
- Tailwind CSS for styling
- Vite for build tooling

## Development Tools
- Docker Compose for the debug environment
- Container for app split into CI, Dev, and Prod sections
- Pre-commit hooks for linting, types, and formatting
- UV for depenacy management
- Pytest for Python testing

## CI/CD
- Github Actions for CI/CD
- One set of pipelines for building the app container, both CI and Prod
- One set of pipelines for linting, formatting, and tests
- One set of pipelines for tagging, releases, and development builds
- Modular actions for future reuse and templating
