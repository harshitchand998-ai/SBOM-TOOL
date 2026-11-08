# Scanner Data Contract Specification

This document defines the formal data contract for the `npm-sbom-tool` project scanner (`scanProject` and `scanProjectSync`). It serves as the canonical reference for scanner inputs, outputs, data models, error handling, workspace discovery, and behavioral semantics.

---

## 1. Scanner Input Specification

The scanner entry point is exported both asynchronously and synchronously from `src/scanner/index.js` (and re-exported by `src/index.js`):

```javascript
// Asynchronous entry point
async function scanProject(projectPath)

// Synchronous entry point (guaranteed identical structured result)
function scanProjectSync(projectPath)
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `projectPath` | `string` | Yes | Absolute or relative filesystem path to the target project directory. |

### Validation & Path Normalization Rules

1. **Type & Non-Empty Validation**:
   - `projectPath` must be a non-empty `string`.
   - If `projectPath` is `null`, `undefined`, a non-string type, an empty string `""`, or a string containing only whitespace `"   "`, the scan immediately terminates with status `'failed'` and an error with code `PROJECT_NOT_FOUND`.
2. **Filesystem Resolution**:
   - Relative paths are normalized to canonical absolute paths via `node:path.resolve(projectPath)`.
   - Trailing slashes and platform-specific backslashes (`\`) are normalized automatically to canonical forward slashes (`/`).
3. **Directory Check**:
   - The resolved path must exist on disk and must be a directory (`stats.isDirectory() === true`).
   - If the path does not exist or points to a file, the scanner returns status `'failed'` with error code `PROJECT_NOT_FOUND`.
4. **Unsupported Package Manager Check**:
   - If alternative package manager lockfiles (`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`) exist in the project root, the scan returns status `'failed'` with error code `UNSUPPORTED_PACKAGE_MANAGER`.

---

## 2. Scanner Output Contract

The scanner returns a JavaScript Promise (or object for sync) resolving to a uniform structured object. The result shape is guaranteed to contain all standard keys across all operational statuses (`'complete'`, `'partial'`, `'failed'`).

### Top-Level Object Schema

```typescript
interface ScanResult {
  status: 'complete' | 'partial' | 'failed';
  projectPath: string;
  projectMetadata: ProjectMetadata | null;
  lockfileVersion: number | null;
  errors: ScanErrorItem[];
  warnings: ScanErrorItem[];
  components: Component[];
  dependencyEdges: Record<string, string[]>;
  bom: CycloneDXBom | null;
  validation: ValidationResult | null;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}
```

### Field Definitions

| Field | Type | Description |
|---|---|---|
| `status` | `'complete' \| 'partial' \| 'failed'` | Overall outcome of the scan. |
| `projectPath` | `string` | Normalized absolute path of the scanned target. |
| `projectMetadata` | `{ name: string, version: string } \| null` | Root package metadata from `package.json`, or `null` if manifest is missing/invalid. |
| `lockfileVersion` | `number \| null` | Detected npm lockfile version (`2` or `3`), or `null` if missing/unparseable. |
| `errors` | `ScanErrorItem[]` | Fatal or blocking issues encountered during the scan (or workspace manifest errors). |
| `warnings` | `ScanErrorItem[]` | Non-fatal conditions (e.g. Unresolved optional dependencies, incompatible workspace ranges, fallback warnings). |
| `components` | `Component[]` | Flat list of all discovered components (root package + local workspaces + third-party dependencies). |
| `dependencyEdges` | `Record<string, string[]>` | Adjacency list mapping parent component `bomRef` to array of child `bomRef`s. |
| `bom` | `object \| null` | Generated CycloneDX 1.7 JSON SBOM (`null` for `'partial'` and `'failed'` scans). |
| `validation` | `ValidationResult \| null` | Structural validation result (`{ valid, errors, warnings }`), or `null` when no BOM is generated. |

---

## 3. Scan Status Semantics

1. **`complete`**:
   - Both `package.json` and a supported `package-lock.json` (v2 or v3) were discovered and parsed.
   - All components, exact resolved versions, integrity hashes, and dependency graph edges were extracted.
   - Any local npm workspaces were discovered and validated against lockfile symlinks.
   - A valid CycloneDX 1.7 JSON SBOM is populated in `bom`.
   - `errors` array is empty (`[]`).
2. **`partial`**:
   - `package.json` was parsed, but `package-lock.json` is missing, unparseable, uses an unsupported version (e.g. V1), or non-fatal workspace errors occurred (e.g., malformed workspace manifest).
   - Direct dependencies declared in manifests are returned with version ranges (`version: null`, `versionRange: "^1.0.0"`).
   - Transitive dependencies cannot be reliably resolved and are not fabricated.
   - `bom` is `null` because an incomplete manifest-only scan cannot guarantee exact CycloneDX SBOM integrity.
   - Non-fatal warnings and/or fallback errors explaining the lockfile absence or limitation are populated.
3. **`failed`**:
   - Target path does not exist, is not a directory, or has invalid permissions.
   - Root `package.json` is missing or contains invalid/unparseable JSON.
   - Unsupported package managers (`yarn.lock`, `pnpm`, `bun`) are detected.
   - `components` is empty (`[]`), `dependencyEdges` is empty (`{}`), and `bom` is `null`.

---

## 4. Component Data Model

Each component in `components` conforms to the following schema:

```typescript
interface Component {
  name: string;
  version: string | null;
  versionRange?: string;
  description?: string;
  license?: string;
  ecosystem: 'npm';
  purl: string | null;
  bomRef: string;
  dependencyType: 'root' | 'direct' | 'transitive' | 'workspace';
  dependencyGroups: string[];
  integrity: string | null;
  resolved: string | null;
  installPaths: string[];
  optional: boolean;
  dev: boolean;
  devOptional: boolean;
  isRoot?: boolean;
  isFirstParty?: boolean;
  classification?: 'first-party' | 'third-party';
  origin?: 'first-party' | 'third-party';
  location?: {
    resolved: string;
    relative: string;
  };
  path?: string;
  relativePath?: string;
  workspaceDependencies?: string[];
}
```

### Component Field Rules

- **`name`**: Exact npm package name (including scope if applicable, e.g. `@babel/core` or `@company/shared-utils`).
- **`version`**: Exact resolved semantic version string from lockfile or workspace manifest (e.g. `'2.1.3'`). In manifest-only partial scans of third-party packages, `version` is `null`.
- **`versionRange`**: Declared version range from manifest (e.g. `'^4.18.0'`), populated during partial scans.
- **`ecosystem`**: Constant string `'npm'`.
- **`purl`**: Standard Package URL format:
  - Standard package: `pkg:npm/ms@2.1.3`
  - Scoped package: `pkg:npm/%40scope/pkg@1.0.0` (scope `@` encoded as `%40`)
  - Manifest-only partial scan: `null` for unconfirmed third-party packages (valid purls require exact resolved versions).
- **`bomRef`**: Unique identifier used across dependency edges and CycloneDX SBOM:
  - Complete scan: Matches `purl`, with optional `#<location>` disambiguation if identical package names/versions collide.
  - Manifest-only partial scan: `pkg:npm/<name>@<versionRange>`.
- **`dependencyType`**:
  - `'root'`: The root application being scanned (`isRoot: true`).
  - `'workspace'`: Local first-party npm workspace package discovered in the repository.
  - `'direct'`: External third-party package directly declared in root `package.json` and resolved in root graph edges.
  - `'transitive'`: Indirectly required by a parent dependency.
- **`dependencyGroups`**: Array of root declaration groups (`'dependencies'`, `'devDependencies'`, `'optionalDependencies'`, `'peerDependencies'`). Direct dependencies reflect their declared group; transitive dependencies have `[]`.
- **`integrity`**: Subresource integrity hash from lockfile (e.g. `sha512-...` or `sha1-...`), or `null` if unavailable or in partial scans.
- **`resolved`**: Distribution tarball URL from lockfile (e.g. `https://registry.npmjs.org/ms/-/ms-2.1.3.tgz`), or `null` if unavailable or in partial scans. Always `string | null` (never boolean).
- **`installPaths`**: Array of lockfile package paths where this component was resolved (e.g. `['node_modules/ms']` or `['node_modules/pkg-a']` for workspace symlinks).
- **`optional`**: Boolean indicating optional dependency status.
- **`dev`**: Boolean indicating development dependency status.
- **`devOptional`**: Boolean indicating dev-optional status.
- **`isRoot`**: Boolean flag set to `true` exclusively on the root application component.
- **`isFirstParty`**: Boolean flag set to `true` on the root application and all local workspace components; `false` on external registry packages.
- **`classification`**: String `'first-party'` for root and workspaces; `'third-party'` for external registry packages.
- **`origin`**: String `'first-party'` or `'third-party'`.
- **`location`**: Object containing `{ resolved: string, relative: string }` pointing to the physical filesystem directory of first-party components.
- **`path`**: Absolute filesystem path for first-party components.
- **`relativePath`**: Project-root-relative path for first-party components (e.g., `.` for root, `packages/core` for workspaces).
- **`workspaceDependencies`**: Array of local workspace names directly depended upon.

---

## 5. First-Party Component Discovery & Workspace Resolution

### Root Application Representation
- The root project declared in the root `package.json` is always discovered and included in `components`.
- Root has `isRoot: true`, `isFirstParty: true`, `classification: 'first-party'`, `origin: 'first-party'`, `dependencyType: 'root'`, and `location: { resolved: <rootPath>, relative: '.' }`.
- In CycloneDX SBOM output, the root application is placed in `metadata.component` (`type: 'application'`), while non-root components are placed in `bom.components` (`type: 'library'`).

### Local npm Workspace Packages
- Supported workspace manifest formats:
  - Array format: `"workspaces": ["packages/*", "apps/**"]`
  - Object format: `"workspaces": { "packages": ["packages/*"] }`
- Supported pattern syntax:
  - Single wildcard: `packages/*`
  - Recursive wildcard: `packages/**` and `packages/**/client`
  - Single-character wildcard: `packages/pkg-?`
  - Negation: `!packages/ignored-pkg`
  - Normalization: Forward slashes and Windows backslashes (`packages\*`, `.\packages\*`) are automatically normalized.
- Workspace packages are discovered by inspecting manifests in matched directories:
  - Valid manifests are added to `components` with `dependencyType: 'workspace'`, `isFirstParty: true`, and `classification: 'first-party'`.
  - Directories missing `package.json` report `PACKAGE_FILE_NOT_FOUND` errors.
  - Directories with malformed `package.json` report `INVALID_PACKAGE_FILE` errors while preserving discovery of valid packages.

### Lockfile Validation & Symlink Handling
- In npm lockfile v2/v3, workspaces are referenced as:
  1. A directory entry (e.g. `"packages/pkg-a"`).
  2. A symlink entry in `node_modules/` (e.g. `"node_modules/pkg-a": { "resolved": "packages/pkg-a", "link": true }`).
- The scanner detects `pkgEntry.link: true` and resolves the symlink to the corresponding discovered workspace package:
  - The symlink path is recorded in the workspace component's `installPaths`.
  - The symlink is mapped in the dependency resolver to the workspace component's `bomRef`.
  - No unsupported layout warning or missing dependency warning is emitted for valid workspace links.
- Workspace dependencies are verified against the lockfile:
  - If a workspace declares a dependency that cannot be resolved in the lockfile, the scanner emits an `UNRESOLVED_DEPENDENCY` warning and does not invent an edge.
  - Version compatibility is checked via semver range evaluation (`isVersionCompatible`). If a declared range is incompatible with the local workspace version, an `UNRESOLVED_DEPENDENCY` warning is reported and the edge is omitted.

### Disambiguation and Conflict Prevention
- **Root-to-workspace name collision**: If a workspace has the same name as the root package, unique `bomRef`s are preserved using location fragment suffixes (e.g. `pkg:npm/name@1.0.0#packages/core`).
- **Duplicate workspace names**: If two workspace packages share the exact same package name, an `UNSUPPORTED_WORKSPACE_LAYOUT` error is recorded, unique `bomRef`s are maintained, and ambiguous cross-references between them are rejected to avoid linking to the wrong package.
- **Third-party vs First-party classification**: External registry packages with the same name as a local workspace are not misclassified as first-party; remote resolution URLs and registry integrity hashes are inspected to maintain strict third-party classification.

---

## 6. Error & Warning Contract

Errors and warnings follow a structured object pattern:

```typescript
interface ScanErrorItem {
  code: string;
  message: string;
  file?: string;
  path?: string;
  packageManager?: string;
  lockfileVersion?: number;
  dependency?: string;
  parent?: string;
  workspace?: string;
  declaredRange?: string;
  localVersion?: string;
  originalError?: string;
}
```

### Standard Error Codes (`ErrorCodes`)

| Error Code | Severity | Trigger Scenario |
|---|---|---|
| `PROJECT_NOT_FOUND` | Fatal (Failure) | Path does not exist, is not a directory, is empty, or has invalid type. |
| `PROJECT_ACCESS_DENIED` | Fatal (Failure) | Filesystem permission denied on target directory. |
| `PACKAGE_FILE_NOT_FOUND` | Fatal (Failure) / Warning | Fatal when root `package.json` missing; warning when `package-lock.json` missing (triggers partial scan); non-fatal error when a workspace directory lacks `package.json`. |
| `INVALID_PACKAGE_FILE` | Fatal (Failure) / Fallback | Fatal when root `package.json` is malformed JSON; triggers partial scan fallback when `package-lock.json` is malformed; non-fatal error when a workspace `package.json` is malformed. |
| `UNSUPPORTED_LOCKFILE_VERSION` | Fallback | Lockfile version is not 2 or 3 (e.g. Version 1); falls back to partial scan. |
| `UNSUPPORTED_PACKAGE_MANAGER` | Fatal (Failure) | Target contains `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, or `bun.lockb`. |
| `UNSUPPORTED_WORKSPACE_LAYOUT` | Fatal (Failure) / Warning | Malformed `workspaces` config, workspace pattern escaping project root, empty workspace patterns, unresolvable symlinks, or duplicate workspace package names. |
| `UNRESOLVED_DEPENDENCY` | Warning | Declared dependency cannot be resolved from the lockfile, or declared workspace range is incompatible with local workspace version. |
| `SCAN_ERROR` | Fatal (Failure) | Unexpected runtime error during dependency resolution or SBOM generation. |

---

## 7. CycloneDX BOM Generation & Validation Contract

### CycloneDX Specification Version
- `npm-sbom-tool` generates Software Bill of Materials conforming to **CycloneDX JSON Specification Version 1.7**.
- Top-level BOM structure includes `bomFormat: 'CycloneDX'`, `specVersion: '1.7'`, `serialNumber: 'urn:uuid:<uuid>'`, and `version: 1`.

### Structural Validation Rules (`validateStructure`)
The scanner executes built-in, offline structural validation (`validateStructure(bom)`) on all generated BOMs before delivering the scan result. The validator checks:

1. **Top-Level Requirements**:
   - `bomFormat` must equal `"CycloneDX"`.
   - `specVersion` must be a supported version string (`"1.7"`, `"1.6"`, `"1.5"`, `"1.4"`).
   - `version` must be a positive integer >= 1.
   - `serialNumber` must be a valid RFC 4122 UUID URN (`urn:uuid:<uuid>`).
2. **Metadata Requirements**:
   - `metadata` object is mandatory.
   - `metadata.timestamp` must be a valid ISO-8601 date string.
   - `metadata.tools` must be an object or array.
   - `metadata.component` is mandatory and represents the root application with non-empty `type`, `name`, and `bom-ref`.
   - If `purl` is present on `metadata.component`, it must validate against the PURL specification.
3. **Component Requirements**:
   - Every component in `bom.components` must be an object with non-empty `type`, `name`, `version`, and `bom-ref`.
   - PURLs (`comp.purl`) must validate against Package URL format rules.
   - Component `bom-ref` values must be strictly unique.
   - **Collision Detection**: Collisions between `metadata.component['bom-ref']` and any entry in `bom.components` are rejected.
4. **Dependency Graph Integrity**:
   - `bom.dependencies` must be an array when present.
   - Each entry must possess a valid `ref` and an array of `dependsOn` child references.
   - **No Nonexistent References**: Every `ref` in `dependencies` must reference a known component (`metadata.component` or `components`).
   - **No Dangling Edges**: Every target reference in `dependsOn` must exist in `metadata.component` or `components`.
   - **No Duplicates**: Duplicate dependency entries for the same `ref` and duplicate child references in `dependsOn` are rejected.
   - **Root Dependency Entry**: The root application component MUST possess a dependency entry in `bom.dependencies`.
5. **Result Structure**:
   - Returns `{ valid: boolean, errors: string[], warnings: string[] }`.
   - All errors clearly identify the invalid field, index, component, or dependency reference.
   - The validator never throws unexpected exceptions on malformed input.

### Package URL Validation (`validatePurl`)
The validator inspects package URLs to ensure:
- Scheme prefix is strictly `pkg:`.
- Package manager type is valid (e.g. `npm`).
- Package name is non-empty, correctly preserving URL-encoded namespaces (`%40scope/pkg`).
- Version is non-empty when `@` is present.
- Qualifiers (`?`) and subpaths (`#`) are safely parsed and validated.

### Scanner Pipeline Integration & Partial Scan Semantics
1. **Complete Scans**:
   - CycloneDX generation produces a complete BOM.
   - `validateStructure(bom)` is executed.
   - If valid: `status: 'complete'`, `bom: <BOM>`, `validation: { valid: true, errors: [], warnings: [] }`.
   - If invalid: `status: 'partial'`, `bom: null` (invalid BOM is never returned), validation errors are recorded as `SCAN_ERROR` in `errors`, and `validation: { valid: false, errors: [...] }`.
2. **Partial Scans**:
   - When a lockfile is missing, corrupted, or unsupported, the scanner completes in `'partial'` mode.
   - `bom: null` and `validation: null` are preserved.
   - The scanner does not attempt to validate or emit a nonexistent or incomplete BOM.
3. **CLI Behavior**:
   - The CLI writes the generated CycloneDX SBOM to disk only when `status === 'complete'`, `bom !== null`, and `validation.valid === true`.
   - If validation fails, the CLI writes no SBOM output, logs all validation errors to stderr, and exits with non-zero exit code (`1`).
   - On partial scans, the CLI writes a `.partial.json` diagnostic report (not a `.cdx.json` SBOM) and exits with code `0`.
   - On failed scans, the CLI writes no output and exits with code `1`.

### JSON Schema Validation Status (`validateAgainstSchema`)
- **Built-in Structural Validation**: Fully self-contained, offline, and zero-network.
- **Official Schema Validation**: Exported via `validateAgainstSchema(bom, schema)` using `ajv` and `ajv-formats`. Callers may provide an official CycloneDX JSON schema object at runtime. Official multi-megabyte schema files are not bundled by default to maintain lightweight footprint and zero-network operational constraints.

---

## 8. Fixture Reference Matrix

| Fixture Name | Category | Manifest | Lockfile | Expected Status | Key Validations |
|---|---|---|---|---|---|
| `simple-project` | Standard | Valid | v3 | `complete` | Direct (`is-odd`) vs transitive (`is-number`); valid CycloneDX BOM. |
| `transitive-project` | Deep graph | Valid | v3 | `complete` | Multi-level chain (`accepts` -> `mime-types` -> `mime-db`). |
| `mixed-dependencies-project` | Dep groups | Valid | v3 | `complete` | Prod, dev, optional, and peer dependencies all tracked. |
| `multiple-versions-project` | Version conflict | Valid | v3 | `complete` | Retains multiple versions of same package (`shared-dep` 1.5.0 & 2.0.0). |
| `scoped-package-project` | Scoped pkgs | Valid | v3 | `complete` | Scoped Package URLs (`pkg:npm/%40babel/core@...`). |
| `no-node-modules-project` | Offline scan | Valid | v3 | `complete` | Resolves completely without physical `node_modules` folder. |
| `lockfile-v2-project` | Lockfile v2 | Valid | v2 | `complete` | Full support for npm lockfile version 2. |
| `zero-deps-project` | Edge case | Valid | v3 | `complete` | Zero dependencies; root component only; empty BOM components array. |
| `workspace-with-lockfile-project` | Workspaces | Valid | v3 | `complete` | Full workspace project with lockfile v3, symlinks, workspace chains, and CycloneDX BOM. |
| `workspace-simple-project` | Workspaces | Valid | None | `partial` | Single workspace package; root + workspace component discovered. |
| `workspace-multi-project` | Workspaces | Valid | None | `partial` | Multiple workspaces (apps, packages) with object configuration. |
| `workspace-overlapping-project` | Workspaces | Valid | None | `partial` | Overlapping workspace patterns deduplicated safely. |
| `workspace-duplicate-project` | Workspaces | Valid | None | `partial` | Duplicate workspace names report `UNSUPPORTED_WORKSPACE_LAYOUT`. |
| `workspace-invalid-project` | Workspaces | Valid | None | `partial` | Invalid workspace manifest reports `INVALID_PACKAGE_FILE` while valid package is kept. |
| `missing-lockfile-project` | Fallback | Valid | None | `partial` | Manifest-only scan; version ranges recorded; `bom: null`. |
| `unsupported-lockfile-project`| Fallback | Valid | v1 | `partial` | Lockfile v1 detected; emits error code and falls back to partial. |
| `invalid-lockfile-project` | Fallback | Valid | Malformed | `partial` | Corrupted lockfile JSON falls back to partial scan. |
| `unresolved-deps-project` | Warning | Valid | Incomplete | `complete` | Unresolved dependency produces `UNRESOLVED_DEPENDENCY` warning. |
| `missing-manifest-project` | Error | None | v3 | `failed` | Fails with `PACKAGE_FILE_NOT_FOUND`. |
| `empty-project` | Error | None | None | `failed` | Fails with `PACKAGE_FILE_NOT_FOUND`. |
| `invalid-project` | Error | Malformed | None | `failed` | Malformed `package.json` fails with `INVALID_PACKAGE_FILE`. |
| `unsupported-project` | Error | Valid | `yarn.lock` | `failed` | Yarn detected; fails with `UNSUPPORTED_PACKAGE_MANAGER`. |

---

## 9. Supported Features and Remaining Limitations

### Supported Features
- Complete npm workspace discovery for array (`["packages/*"]`) and object (`{ "packages": ["packages/*"] }`) declarations.
- Flexible globbing: `*`, `**`, `?`, pattern negation (`!`), and Windows backslashes (`\`).
- First-party component tagging: `isFirstParty: true`, `classification: 'first-party'`, `origin: 'first-party'`.
- Third-party component tagging: `isFirstParty: false`, `classification: 'third-party'`, `origin: 'third-party'`.
- Lockfile v2/v3 symlink resolution: `link: true` entries map to local workspace components and populate `installPaths`.
- Full CycloneDX 1.7 JSON SBOM generation for complete scans, placing root application in `metadata.component` and workspaces/libraries in `components`.
- Complete structural validation (`validateStructure`) catching missing fields, invalid metadata, invalid PURLs, duplicate `bom-ref`s, and dangling dependency edges.
- Zero-network, offline operation by default with optional schema validation (`validateAgainstSchema`).
- Protected CLI writing: outputs valid CycloneDX SBOM on success, emits diagnostic `.partial.json` on partial scans, and exits with non-zero on validation failure.
- Complete synchronous (`scanProjectSync`) and asynchronous (`scanProject`) scanner parity.

### Remaining Limitations
- Non-npm package managers (`yarn`, `pnpm`, `bun`) remain unsupported and trigger `UNSUPPORTED_PACKAGE_MANAGER`.
- npm lockfile version 1 does not contain full packages tree information and triggers fallback to a partial scan.
- Workspace projects without `package-lock.json` are scanned in partial mode; exact resolved versions and CycloneDX SBOM generation require a supported lockfile.
- Incompatible workspace version ranges are not linked as workspace dependencies.
- Official multi-megabyte CycloneDX JSON schema is not bundled locally; structural validation is performed natively while schema validation is available when a schema is provided by the caller.
