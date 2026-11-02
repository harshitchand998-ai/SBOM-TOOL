# npm-sbom-tool

A lightweight, reusable JavaScript engine and tool for generating Software Bill of Materials (SBOM) from npm projects.

## Project Structure

```text
├── package.json               # Project metadata, dependencies, bin, and scripts
├── .gitignore                 # Git ignore configuration
├── README.md                  # Project documentation and setup guide
├── docs/
│   └── scanner-contract.md    # Formal scanner data contract specification
├── fixtures/                  # 15 comprehensive test fixture projects
├── src/
│   ├── index.js               # Main package entry point
│   ├── engine/                # Reusable engine core
│   │   └── index.js           # Initial decoupled engine entry point
│   ├── scanner/               # npm dependency scanner orchestration
│   │   └── index.js           # scanProject implementation
│   ├── fileDiscovery.js       # Target path and lockfile discovery
│   ├── parser.js              # package.json and package-lock.json parsing
│   ├── dependencyResolver.js  # Graph resolution, multiple versions, and classifications
│   ├── cyclonedxGenerator.js  # CycloneDX 1.7 JSON SBOM generator
│   ├── validator.js           # Structural SBOM validation
│   ├── errors.js              # Standard error codes and status enums
│   └── cli.js                 # Command-line interface
└── test/
    ├── engine.test.js         # Engine entry point tests
    ├── parser.test.js         # Manifest and lockfile parser tests
    ├── dependencyResolver.test.js # Dependency resolution tests
    ├── cyclonedxGenerator.test.js # SBOM output and graph tests
    └── scanner.test.js        # End-to-end integration tests (15 fixtures)
```

## Prerequisites

- **Node.js**: v18.0.0 or later (Node.js 20+ recommended)
- **npm**: v9.0.0 or later

## Installation

Install dependencies using npm:

```bash
npm install
```

## Available Scripts

- **`npm test`**: Runs the complete automated test suite via Node's native test runner (`node --test`).
- **`npm run test:scanner`**: Runs integration tests for the project scanner across all fixture scenarios.
- **`npm run test:parser`**: Runs unit tests for `package.json` and `package-lock.json` parsing.
- **`npm run test:resolver`**: Runs unit tests for dependency graph resolution and classification.
- **`npm run test:cyclonedx`**: Runs unit tests for CycloneDX 1.7 SBOM generation and schema validation.
- **`npm run scan <path>`**: Runs the CLI scanner against a specified target project path.
- **`npm run check`**: Runs syntax validation checks across all source files using `node --check`.

## Scanner Data Contract

For detailed input/output models, component schemas, error codes, and fixture mappings, see the [Scanner Contract Specification](docs/scanner-contract.md).

## Programmatic Usage

The project exports both the initial decoupled engine and the npm scanner:

```javascript
import { scanProject, runEngine } from "npm-sbom-tool";

// 1. Scan an npm project and obtain structured results and CycloneDX SBOM
const result = await scanProject("./fixtures/simple-project");

console.log(result.status); // 'complete' | 'partial' | 'failed'
console.log(result.projectMetadata); // { name: 'simple-project', version: '1.0.0' }
console.log(result.components); // Array of discovered components
console.log(result.dependencyEdges); // Graph adjacency map
console.log(result.bom); // CycloneDX 1.7 JSON object (or null)

// 2. Core engine entry point (Order 1)
const engineData = await runEngine("./fixtures/simple-project");
console.log(engineData.status); // 'initialized'
```

## Command-Line Usage

```bash
# Scan a project and generate an SBOM
node src/cli.js scan ./path/to/project --output ./bom.cdx.json

# Using npm script
npm run scan fixtures/simple-project
```
