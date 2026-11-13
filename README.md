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
│   ├── vulnerabilityMatcher.js # SemVer comparison & OSV range evaluation
│   ├── vulnerabilityFindings.js # Finding normalization, severity, & deduplication
│   ├── vulnerabilityChecker.js # Vulnerability pipeline orchestration
│   ├── anomalyDetector.js     # SBOM metadata and dependency graph anomaly detection
│   ├── dependencyComparison.js # Standalone two-SBOM inventory diff & change classifier
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
    ├── vulnerabilityMatcher.test.js # Version matching & range evaluation tests
    ├── vulnerabilityFindings.test.js # Finding normalization & deduplication tests
    ├── vulnerabilityIntegration.test.js # End-to-end vulnerability pipeline tests
    ├── anomalyDetector.test.js # SBOM anomaly detection unit & integration tests
    ├── dependencyComparison.test.js # SBOM inventory comparison tests
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
- **`npm run test:matcher`**: Runs unit tests for semantic version matching and range evaluation.
- **`npm run test:findings`**: Runs unit tests for finding extraction and deduplication.
- **`npm run test:vuln`**: Runs comprehensive integration tests for vulnerability detection.
- **`npm run test:anomaly`**: Runs unit and integration tests for SBOM anomaly detection.
- **`npm run test:compare`**: Runs unit tests for SBOM dependency inventory comparison.
- **`npm run test:cli`**: Runs the CLI command integration test suite.
- **`npm run scan <path>`**: Runs the CLI scanner against a specified target project path.
- **`npm run sbom <path>`**: Generates a CycloneDX SBOM for a target project path.
- **`npm run audit <path>`**: Runs vulnerability and anomaly security analysis on a target project.
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

// 1. Asynchronously scan an npm project (includes anomaly detection)
const result = await scanProject("./fixtures/workspace-with-lockfile-project");

console.log(result.status);           // 'complete' | 'partial' | 'failed'
console.log(result.projectMetadata);  // { name: 'workspace-with-lockfile-project', version: '1.0.0' }
console.log(result.components);       // Array of discovered components (root + workspaces + dependencies)
console.log(result.dependencyEdges);  // Adjacency list mapping bomRef -> [child bomRefs]
console.log(result.bom);              // CycloneDX 1.7 JSON SBOM object (or null for partial/failed)
console.log(result.validation);       // { valid: true, errors: [], warnings: [] } (or null if no BOM)
console.log(result.anomalies);        // { findings: [...], summary: { total, bySeverity, byType } }

// 2. Scan with dependency comparison against a previous SBOM
const compared = await scanProject("./fixtures/simple-project", { previousBom: result.bom });
console.log(compared.comparison);     // { status: 'completed', summary, added, removed, changed, unchanged }

// 3. Synchronously scan an npm project (guaranteed identical result)
const syncResult = scanProjectSync("./fixtures/simple-project");
console.log(syncResult.status);       // 'complete'
console.log(syncResult.validation.valid); // true

// 4. Standalone structural validation of any CycloneDX BOM
const validation = validateStructure(result.bom);
console.log(validation.valid);        // true
console.log(validation.errors);       // []

// 5. Standalone PURL validation
const purlCheck = validatePurl("pkg:npm/%40babel/core@7.24.0");
console.log(purlCheck.valid);         // true
```

## Command-Line Interface (CLI)

`npm-sbom-tool` provides a command-line interface executable via `sbom-tool`, `npm-sbom-tool`, or directly via `node src/cli.js`.

### 1. Invocation & Global Options

```bash
# Display general help and available commands
sbom-tool --help

# Display tool version
sbom-tool --version
```

Global options:
- `--help, -h`: Show general help or command-specific help.
- `--version, -V`: Display the installed version.

Available commands:
- `scan`: Scan an npm project and inspect its dependency tree.
- `sbom`: Generate a standard CycloneDX SBOM document.
- `audit`: Perform security vulnerability and anomaly analysis on a project.

---

### 2. The `scan` Command

The `scan` command inspects an npm project directory, discovers manifests and lockfiles, resolves direct, transitive, and workspace dependencies, and displays a comprehensive summary.

```bash
# Basic scan of the current directory
sbom-tool scan .

# Scan a target project directory
sbom-tool scan ./my-application

# Output structured scan results in JSON format directly to stdout
sbom-tool scan ./my-application --json

# Scan and save the scan report or generated SBOM to a file
sbom-tool scan ./my-application --output ./reports/scan-report.json

# Scan with OSV vulnerability detection enabled
sbom-tool scan ./my-application --vulnerabilities

# Scan and compare dependency inventory against a previous CycloneDX SBOM
sbom-tool scan ./my-application --previous-sbom ./prev-bom.cdx.json

# Display scan-specific options
sbom-tool scan --help
```

Supported options:
- `--output, -o <path>`: Write scan report (or generated SBOM) to file.
- `--json`: Output structured scan results in JSON format to stdout.
- `--vulnerabilities, -v`: Enable OSV vulnerability analysis for discovered dependencies.
- `--previous-sbom <path>`: Path to a previous CycloneDX SBOM JSON file for dependency comparison.
- `--help, -h`: Show scan command help.

Example terminal output:
```text
Scanning project: /path/to/my-application

Scan status: complete
Project: my-application@1.0.0
Lockfile version: 3
Components discovered: 25
Direct dependencies: 8
Transitive dependencies: 17
Workspace packages: 2
```

---

### 3. The `sbom` Command

The `sbom` command generates an industry-standard **CycloneDX 1.7** JSON Software Bill of Materials (SBOM) for complete npm projects.

```bash
# Generate CycloneDX SBOM (defaults to ./sbom.cdx.json)
sbom-tool sbom ./my-application

# Generate CycloneDX SBOM and save to a custom file path
sbom-tool sbom ./my-application --output ./bom.cdx.json
sbom-tool sbom ./my-application -o ./reports/my-app-bom.json

# Output CycloneDX SBOM directly to stdout (useful for piping into jq or files)
sbom-tool sbom ./my-application --json > sbom.json

# Display sbom-specific options
sbom-tool sbom --help
```

Supported options:
- `--output, -o <path>`: Output file path for the generated CycloneDX SBOM. Defaults to `./sbom.cdx.json` when not streaming to stdout.
- `--json`: Output CycloneDX SBOM JSON directly to stdout without diagnostic logs.
- `--help, -h`: Show sbom command help.

Validation & Safety:
- Automatic directory creation: Parent directories of the output path are created automatically if missing.
- Project file protection: Rejects output paths that would overwrite project manifests (`package.json`, `package-lock.json`).
- Directory collision check: Rejects output paths pointing to existing directories.
- Lockfile requirement: A valid lockfile (`package-lock.json`) is required for complete SBOM generation; partial scans exit with an error.

---

### 4. The `audit` Command

The `audit` command evaluates a target project against known security vulnerabilities (via the OSV API) and structural anomalies.

```bash
# Run both vulnerability analysis and anomaly detection (default)
sbom-tool audit ./my-application

# Run vulnerability analysis only
sbom-tool audit ./my-application --vuln

# Run anomaly analysis only
sbom-tool audit ./my-application --anomaly

# Run both analyses explicitly
sbom-tool audit ./my-application --vuln --anomaly

# Save structured audit report to a JSON file
sbom-tool audit ./my-application --output ./audit-report.json

# Output structured audit report in JSON format to stdout
sbom-tool audit ./my-application --json

# Display audit-specific options
sbom-tool audit --help
```

Supported options:
- `--vuln, -v`: Perform vulnerability analysis only (or explicitly).
- `--anomaly, -a`: Perform anomaly analysis only (or explicitly).
- `--output, -o <path>`: Output file path for the structured audit report JSON.
- `--json`: Output structured audit report JSON directly to stdout.
- `--help, -h`: Show audit command help.

Example terminal output:
```text
Security Audit

Project: my-application@1.0.0
Path: /path/to/my-application

Dependencies scanned: 25

--- Vulnerabilities ---
Status: COMPLETED
Packages checked: 25/25
Vulnerabilities found: 2
Critical: 0
High: 1
Medium: 1
Low: 0

Vulnerability Findings:
  • GHSA-p6mc-m468-83gw [CVSS_V3: 7.5] - lodash@4.17.15 (transitive) (Fixed in: 4.17.21)
    Summary: Prototype Pollution in lodash

--- Anomalies ---
Anomalies detected: 1 (errors: 0, warnings: 1, info: 0)
  ⚠ [MISSING_PURL] custom-pkg: Component is missing a Package URL (PURL).

Audit completed (Status: completed).
```

---

### 5. Error Handling & Exit Codes

The CLI returns standard, meaningful process exit codes:

| Exit Code | Meaning | Scenarios |
|---|---|---|
| `0` | Success | Command completed successfully (including complete scans, partial scans with warnings, and audits with findings). |
| `1` | Error | Invalid command, missing/unrecognized options, nonexistent project directory, manifest parsing failure, missing lockfile for `sbom`, BOM validation failure, or file write failure. |

All errors are reported with actionable human-readable messages without exposing internal stack traces by default. Diagnostic and error messages are routed to `stderr`, keeping `stdout` clean for JSON consumers.

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
| `RATE_LIMITED` | HTTP 429 rate limit exceeded. |
| `INVALID_INPUT` | Package object missing or has empty name/version/ecosystem. |
| `INVALID_RESPONSE` | Malformed or unexpected JSON response. |

When using `queryPackages`, individual failures are captured per-package in the `error` field without failing the entire batch.

## Integrated Vulnerability Detection Pipeline

The vulnerability detection pipeline connects SBOM dependency generation with the OSV API and semantic version matching engine.

### How It Works

1. **Extraction & Deduplication**: Extracts all third-party dependencies from the resolved SBOM or scan result. Root applications and first-party local workspace packages are excluded from external queries. Packages are deduplicated by `name@version` so each unique version is queried only once.
2. **OSV API Queries**: Dependencies are queried against the official OSV API (`https://api.osv.dev/v1/query`) in concurrent batches (default concurrency: 8, configurable).
3. **SemVer Range Matching**: Every advisory is evaluated against the installed semantic version using native SemVer 2.0.0 rules:
   - `introduced`: inclusive lower bound (or `'0'` for beginning of time).
   - `fixed`: exclusive upper bound (version `< fixed` is vulnerable, `>= fixed` is unaffected).
   - `last_affected`: inclusive upper bound.
   - `limit`: exclusive upper bound.
4. **Direct & Transitive Classification**: Leverages the CycloneDX dependency graph to accurately classify each finding as `direct` or `transitive`.
5. **Metadata Extraction & Deduplication**: Extracts CVSS and ecosystem severity scores, semantic fixed versions (excluding git hashes), aliases, summaries, and references. Identical findings for the same vulnerability, package, and version are merged cleanly.

### Enabling Vulnerability Detection

#### CLI Flag
```bash
node src/cli.js scan ./path/to/project --vulnerabilities
# or short flag:
node src/cli.js scan ./path/to/project -v
```

#### Programmatic API
```javascript
import { scanProject, checkVulnerabilities } from 'npm-sbom-tool';

// 1. Through scanProject options
const result = await scanProject('./fixtures/simple-project', {
  vulnerabilities: true,
  concurrency: 8, // Optional: concurrency limit
  timeout: 10000, // Optional: timeout in ms
});

console.log(result.vulnerabilities.status); // 'completed' | 'partial' | 'failed'
console.log(result.vulnerabilities.findings);

// 2. Standalone vulnerability checker on existing components or BOM
const vulns = await checkVulnerabilities(result.bom);
console.log(vulns.findings);
```

### Interpreting Findings

Each finding object contains:

```typescript
interface VulnerabilityFinding {
  id: string; // OSV or GHSA identifier (e.g., 'GHSA-odd-01')
  aliases: string[]; // Associated CVEs (e.g., ['CVE-2021-99999'])
  packageName: string; // npm package name
  ecosystem: string; // 'npm'
  installedVersion: string; // Exact installed version (e.g., '3.0.1')
  dependencyType: 'direct' | 'transitive' | 'unknown';
  status: 'vulnerable' | 'unable-to-evaluate';
  severity: { type: string; score: string } | null;
  summary: string | null;
  details: string | null;
  affectedRanges: Array<{ type: string; events: Array<object> }>;
  fixedVersions: string[]; // Valid SemVer versions that resolve the issue
  references: Array<{ type: string; url: string }>;
}
```

#### Status Meanings
- **`vulnerable`**: The installed version falls definitively within the advisory's affected SemVer range.
- **`unaffected`**: The installed version is outside the affected range or equal to/above the fixed version (unaffected packages do not produce vulnerability findings).
- **`unable-to-evaluate`**: The advisory contains only non-SemVer ranges (e.g. Git commit SHAs) or malformed range events, preventing deterministic version evaluation. Only included when `options.includeUnableToEvaluate = true`.

#### Overall Scan Status
- **`completed`**: All eligible packages were successfully queried against OSV.
- **`partial`**: One or more package queries encountered network or timeout errors, but other packages succeeded. Successful findings are retained; failed packages are recorded in `errors` and not assumed to be safe.
- **`failed`**: All package queries failed (e.g., complete network outage).

### Failure Isolation & SBOM Independence
Vulnerability API failures are completely isolated from SBOM generation. Even if the network is down or OSV returns HTTP 500/429, the generated CycloneDX SBOM remains 100% valid, intact, and written to disk.

### Limitations
- Only npm ecosystem advisories are evaluated.
- Advisories without SEMVER ranges (e.g. pure Git commit SHAs without version tags) cannot be evaluated against installed npm versions.
- Vulnerability analysis requires a complete scan with a valid lockfile; partial scans (manifest-only) skip vulnerability detection.

## Anomaly Detection

Anomaly detection automatically analyzes generated CycloneDX SBOMs during complete scans to identify metadata inconsistencies, invalid versions, malformed identifiers, and broken graph relationships. Findings are attached to the scan result under `result.anomalies`.

### Anomaly Output Structure

Each anomaly finding contains:

```typescript
interface AnomalyFinding {
  id: string;                                 // e.g. "ANOMALY-001"
  type: string;                               // e.g. "MISSING_PURL", "INVALID_VERSION"
  severity: 'error' | 'warning' | 'info';     // Finding severity level
  affectedComponent: ComponentSnapshot | null;// Associated component metadata
  explanation: string;                        // Clear explanation (why flagged, inconsistency detected, why it matters)
}
```

Each `explanation` explicitly details:
1. **Why the component was flagged** (e.g. missing name, invalid SemVer, unresolvable reference).
2. **What inconsistency or unusual behavior was detected** (e.g. specific field values or graph edges).
3. **Why the finding matters** (impact on supply chain traceability, vulnerability matching, or tooling interoperability).

### Separation from Vulnerabilities & Non-Blocking Nature

- **Strict Separation**: Anomalies are structural and metadata findings, completely separate from OSV security vulnerabilities (`result.vulnerabilities`). Anomalies are never categorized as vulnerabilities.
- **Non-Invalidating**: Anomalies are informational audit findings; they do not cause a valid CycloneDX SBOM to be rejected or invalidated.
- **Failure Resilience**: Anomaly analysis failures are safely caught and never cause a scan to fail.

```javascript
import { detectAnomalies, scanProject } from 'npm-sbom-tool';

// Standalone anomaly detection
const { anomalies, summary } = detectAnomalies(result.bom, { summary: true });

// Integrated in scanProject()
const scanResult = await scanProject('./my-app');
console.log(scanResult.anomalies.findings); // Array of structured anomaly records
console.log(scanResult.anomalies.summary);  // { total, bySeverity, byType }
```

For full details on anomaly types, severity levels, and options, see the [Anomaly Detection Specification](docs/anomaly-detection.md).

## Dependency Comparison

The dependency comparison module compares two SBOM inventories (`previousBom` vs `currentBom`) and classifies dependency changes into **added**, **removed**, **changed** (upgrades, downgrades, metadata changes, non-comparable version changes), and **unchanged** components.

### Integrated Scanning Workflow

Provide a previous SBOM via `options.previousBom` to `scanProject()` or the `--previous-sbom` CLI flag:

```javascript
import { scanProject } from 'npm-sbom-tool';

// Pass previousBom to scanProject
const result = await scanProject('./my-app', { previousBom: previousBomObject });

console.log(result.comparison.status);  // 'completed' | 'failed'
console.log(result.comparison.summary); // { added, removed, changed, unchanged }
console.log(result.comparison.added);   // Added dependencies with explanations
console.log(result.comparison.changed); // Upgraded/downgraded dependencies with explanations
```

When no previous SBOM is provided, normal scanning proceeds with `result.comparison: null`.

### Standalone Usage

```javascript
import { compareInventories, scanProject } from 'npm-sbom-tool';

const previous = await scanProject('./v1-project');
const current = await scanProject('./v2-project');

const comparison = compareInventories(previous.bom, current.bom);

console.log(comparison.status);  // 'completed' | 'failed'
console.log(comparison.summary); // { added, removed, changed, unchanged }
console.log(comparison.changed); // Detailed upgrade, downgrade, and metadata diffs
```

### Accepted Inputs & Output Structure

- **Expected Inputs**: Any pair of CycloneDX BOM objects (`bomFormat: 'CycloneDX'`, `metadata`, or `components` array) or internal `scanProject()` results. Root application entries (`metadata.component` / `isRoot: true`) are excluded by default so empty dependency inventories yield zero counts; pass `{ includeRoot: true }` to include them when comparing `scanResult` objects.
- **Output Shape**:
  ```javascript
  {
    status: 'completed' | 'failed',
    summary: { added: 0, removed: 0, changed: 0, unchanged: 0 },
    added: [],
    removed: [],
    changed: [],
    unchanged: [],
    errors: [],
    warnings: []
  }
  ```

### Change Classifications

- **`added`**: Present in `currentBom` and absent in `previousBom`.
- **`removed`**: Present in `previousBom` and absent in `currentBom`.
- **`upgrade`**: Matched package whose `currentVersion` is strictly greater than `previousVersion` according to SemVer 2.0.0.
- **`downgrade`**: Matched package whose `currentVersion` is strictly less than `previousVersion` according to SemVer 2.0.0.
- **`metadata-changed`**: Version is unchanged (or SemVer-equivalent), while identifiers or metadata (`purl`, `bomRef`, `hashes`, `externalReferences`, `licenses`, `type`, `isFirstParty`) changed.
- **`version-changed`**: Versions differ, but one is missing or non-SemVer (e.g. Git URLs or tags), so neither upgrade nor downgrade is invented.
- **`unchanged`**: Matched package with identical version and metadata.

### Matching Strategy & Limitations

- Components are matched across inventories using a **versionless canonical identity** (`<ecosystem>:<fullName>`), preferring a valid parsed PURL first and falling back to `<ecosystem>:<group/name>` or `<ecosystem>:<name>`. This ensures upgrades/downgrades are paired cleanly rather than reported as a removal plus an addition.
- Multi-version packages (e.g. `shared-dep@1.5.0` and `shared-dep@2.0.0`) are paired in deterministic passes: exact version + metadata matches first, then same-version matches, then matching `bom-ref`, then positional pairing.
- **Limitations**: Non-SemVer version strings cannot be ordered as upgrades or downgrades (`version-changed` + warning emitted); components missing both a valid PURL and a package `name` are skipped with an `UNRESOLVABLE_COMPONENT_IDENTITY` warning; package renames (name changes) appear as a removal plus an addition.

For the complete specification, see [Dependency Comparison Specification](docs/dependency-comparison.md).


