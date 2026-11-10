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
│   ├── index.js               # Main package entry point and public API exports
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
│   ├── validator.js           # Structural and schema SBOM validation (validateStructure, validatePurl)
│   ├── errors.js              # Standard error codes and status enums
│   ├── osvClient.js           # OSV (Open Source Vulnerabilities) API client
│   └── cli.js                 # Command-line interface
└── test/
    ├── engine.test.js         # Engine entry point tests
    ├── parser.test.js         # Manifest and lockfile parser tests
    ├── dependencyResolver.test.js # Dependency resolution tests
    ├── dependencyGraph.test.js    # Graph builder tests
    ├── workspaceDiscovery.test.js # First-party workspace discovery tests
    ├── cyclonedxGenerator.test.js # SBOM output and graph tests
    ├── validator.test.js      # Dedicated structural & schema validation tests (49 tests)
    ├── scanner.test.js        # Scanner contract and fixture tests
    ├── osvClient.test.js      # OSV API client unit tests
    └── integration.test.js    # Full pipeline and CLI integration tests (37 scenarios)
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
- **`npm run test:validator`**: Runs unit tests for CycloneDX structural and schema validation.
- **`npm run test:integration`**: Runs end-to-end pipeline and CLI integration tests.
- **`npm run test:osv`**: Runs unit tests for the OSV vulnerability API client.
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

## CycloneDX SBOM Generation & Structural Validation

`npm-sbom-tool` generates standard **CycloneDX 1.7** JSON Software Bill of Materials (SBOM):

- **Automatic Structural Validation**: Every generated BOM is validated via `validateStructure()` before return. Checks top-level fields, metadata, timestamps, root component, components array, PURL formats, duplicate `bom-ref`s, and dependency edges.
- **Referential Integrity**: Guarantees no dangling references. Every dependency `ref` and child in `dependsOn` must exist in `metadata.component` or `components`.
- **Protected Pipeline**: If validation fails, `status` becomes `'partial'`, `bom` is set to `null`, and validation errors are surfaced in `result.validation` and `result.errors`.
- **Partial Scan Preservation**: When a lockfile is missing or corrupted, `bom: null` and `validation: null` are preserved. The tool never outputs an invalid or fabricated SBOM.
- **Zero Network Dependency**: Built-in structural validation runs completely offline without network calls. Optional schema validation (`validateAgainstSchema`) is available when callers provide a schema object.

## Scanner Data Contract

For complete input/output specifications, component schemas, error codes, and fixture mappings, see the [Scanner Contract Specification](docs/scanner-contract.md).

## Programmatic Usage

```javascript
import {
  scanProject,
  scanProjectSync,
  generateCycloneDX,
  validateStructure,
  validateAgainstSchema,
  validatePurl,
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
console.log(result.validation);       // { valid: true, errors: [], warnings: [] } (or null if no BOM)

// 2. Synchronously scan an npm project (guaranteed identical result)
const syncResult = scanProjectSync("./fixtures/simple-project");
console.log(syncResult.status);       // 'complete'
console.log(syncResult.validation.valid); // true

// 3. Standalone structural validation of any CycloneDX BOM
const validation = validateStructure(result.bom);
console.log(validation.valid);        // true
console.log(validation.errors);       // []

// 4. Standalone PURL validation
const purlCheck = validatePurl("pkg:npm/%40babel/core@7.24.0");
console.log(purlCheck.valid);         // true
```

## Command-Line Usage

```bash
# Scan a project and write CycloneDX SBOM
node src/cli.js scan fixtures/workspace-with-lockfile-project --output ./bom.cdx.json

# Scan a simple project (default output: ./sbom-output.cdx.json)
node src/cli.js scan fixtures/simple-project

# When scanning a partial project (missing lockfile), a diagnostic report is written instead:
node src/cli.js scan fixtures/missing-lockfile-project --output ./bom.cdx.json
# Writes: ./bom.partial.json (exits 0)
```

## OSV Vulnerability API Client

The `osvClient` module queries the [OSV (Open Source Vulnerabilities)](https://osv.dev/) API to retrieve known vulnerabilities for npm dependencies.

### Query a single package

```javascript
import { queryPackage } from 'npm-sbom-tool';

const result = await queryPackage({ name: 'lodash', version: '4.17.20' });
// result.package    → { name: 'lodash', version: '4.17.20', ecosystem: 'npm' }
// result.vulnerabilities → [{ id, summary, details, aliases, severity, references, affected, published, modified }]
```

### Query multiple packages

```javascript
import { queryPackages } from 'npm-sbom-tool';

const results = await queryPackages([
  { name: 'lodash', version: '4.17.20' },
  { name: 'express', version: '4.18.2' },
]);
// Each entry: { package, vulnerabilities } on success
// On per-package failure: { package, vulnerabilities: [], error: { code, message } }
```

### Input

- `name` (string): npm package name.
- `version` (string): Installed version.
- `ecosystem` (string, optional): Defaults to `'npm'`.

### Output

Each vulnerability object contains:

| Field | Type | Description |
|---|---|---|
| `id` | `string \| null` | OSV vulnerability ID (e.g. `GHSA-...`, `CVE-...`). |
| `summary` | `string \| null` | Short vulnerability summary. |
| `details` | `string \| null` | Detailed description. |
| `aliases` | `string[]` | Alternative IDs (e.g. CVE aliases). |
| `severity` | `object[]` | CVSS severity scores. |
| `references` | `object[]` | Advisory URLs and references. |
| `affected` | `object[]` | Affected package/version information. |
| `published` | `string \| null` | Publication timestamp. |
| `modified` | `string \| null` | Last modification timestamp. |

### Error handling

Errors are thrown as `OsvError` with a `code` property:

| Code | Meaning |
|---|---|
| `NETWORK_ERROR` | Network connectivity failure. |
| `REQUEST_TIMEOUT` | Request exceeded 10s timeout. |
| `API_ERROR` | Non-2xx HTTP response from OSV API. |
| `INVALID_RESPONSE` | Malformed or unexpected JSON response. |

When using `queryPackages`, individual failures are captured per-package in the `error` field without failing the entire batch.
