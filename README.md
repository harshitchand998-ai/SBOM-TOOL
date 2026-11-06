# npm-sbom-tool

A lightweight, reusable JavaScript engine and tool for generating Software Bill of Materials (SBOM) from npm projects.

## Project Structure

```text
├── package.json               # Project metadata, dependencies, bin, and scripts
├── .gitignore                 # Git ignore configuration
├── README.md                  # Project documentation and setup guide
├── docs/
│   └── scanner-contract.md    # Formal scanner data contract specification
├── fixtures/                  # Comprehensive test fixture projects (workspaces & standalone)
├── src/
│   ├── index.js               # Main package entry point
│   ├── engine/                # Reusable engine core
│   │   └── index.js           # Decoupled engine entry point
│   ├── scanner/               # npm dependency scanner orchestration
│   │   └── index.js           # scanProject and scanProjectSync implementation
│   ├── fileDiscovery.js       # Target path and lockfile discovery
│   ├── parser.js              # package.json and package-lock.json parsing
│   ├── dependencyResolver.js  # Full graph resolution, multiple versions, and classifications
│   ├── dependencyGraph.js     # Standalone dependency graph builder and edge resolver
│   ├── workspaceDiscovery.js  # First-party component discovery and workspace resolution
│   ├── cyclonedxGenerator.js  # CycloneDX 1.7 JSON SBOM generator
│   ├── validator.js           # Structural and schema SBOM validation
│   ├── errors.js              # Standard error codes and status enums
│   └── cli.js                 # Command-line interface
└── test/
    ├── engine.test.js         # Engine entry point tests
    ├── parser.test.js         # Manifest and lockfile parser tests
    ├── dependencyResolver.test.js # Dependency resolution tests
    ├── dependencyGraph.test.js    # Graph builder tests
    ├── workspaceDiscovery.test.js # First-party workspace discovery tests
    ├── cyclonedxGenerator.test.js # SBOM output and graph tests
    ├── scanner.test.js        # Scanner contract and fixture tests
    └── integration.test.js    # Comprehensive integration tests (22 scenarios)
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
- **`npm run test:scanner`**: Runs integration tests for the project scanner across fixture scenarios.
- **`npm run test:parser`**: Runs unit tests for `package.json` and `package-lock.json` parsing.
- **`npm run test:resolver`**: Runs unit tests for dependency graph resolution and classification.
- **`npm run test:graph`**: Runs unit tests for standalone dependency graph building.
- **`npm run test:workspace`**: Runs unit tests for first-party component and workspace discovery.
- **`npm run test:cyclonedx`**: Runs unit tests for CycloneDX 1.7 SBOM generation and schema validation.
- **`npm run scan <path>`**: Runs the CLI scanner against a specified target project path.
- **`npm run check`**: Runs syntax validation checks across all source files using `node --check`.

## First-Party Component & Workspace Support

`npm-sbom-tool` provides built-in discovery and representation for first-party components:

1. **Root Application**:
   - Always recognized as a first-party component (`isFirstParty: true`, `classification: 'first-party'`, `origin: 'first-party'`).
   - Placed in `metadata.component` in the generated CycloneDX SBOM.

2. **Local npm Workspaces**:
   - Discovers workspaces configured via array syntax (`"workspaces": ["packages/*"]`) or object syntax (`"workspaces": { "packages": ["packages/*"] }`).
   - Supports single wildcards (`*`), recursive wildcards (`**`), single-character wildcards (`?`), and pattern negations (`!pattern`).
   - Resolves workspace symlinks (`link: true`) in `package-lock.json` v2/v3, linking them directly to local components without duplicate entries.
   - Validates declared version ranges with `isVersionCompatible` against local workspace versions.
   - Distinctly classifies first-party workspaces (`isFirstParty: true`, `dependencyType: 'workspace'`) from external registry packages (`isFirstParty: false`, `dependencyType: 'direct' | 'transitive'`).

## Scanner Data Contract

For complete input/output specifications, component schemas, error codes, and fixture mappings, see the [Scanner Contract Specification](docs/scanner-contract.md).

## Programmatic Usage

```javascript
import {
  scanProject,
  scanProjectSync,
  runEngine,
  discoverFirstPartyComponents,
} from "npm-sbom-tool";

// 1. Asynchronously scan an npm project
const result = await scanProject("./fixtures/workspace-with-lockfile-project");

console.log(result.status);           // 'complete' | 'partial' | 'failed'
console.log(result.projectMetadata);  // { name: 'workspace-with-lockfile-project', version: '1.0.0' }
console.log(result.components);       // Array of discovered components (root + workspaces + dependencies)
console.log(result.dependencyEdges);  // Adjacency list mapping bomRef -> [child bomRefs]
console.log(result.bom);              // CycloneDX 1.7 JSON SBOM object (or null for partial/failed)

// 2. Synchronously scan an npm project (guaranteed identical result)
const syncResult = scanProjectSync("./fixtures/simple-project");
console.log(syncResult.status);       // 'complete'

// 3. Standalone first-party component discovery
const fp = await discoverFirstPartyComponents("./fixtures/workspace-simple-project");
console.log(fp.root);                 // Root component
console.log(fp.workspaces);           // Discovered workspace components
```

## Command-Line Usage

```bash
# Scan a project and display output
npm run scan fixtures/workspace-with-lockfile-project

# Scan with CLI directly
node src/cli.js scan fixtures/simple-project --output ./bom.cdx.json
```
