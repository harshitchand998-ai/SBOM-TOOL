# Scanner Data Contract Specification

This document defines the formal data contract for the `npm-sbom-tool` project scanner (`scanProject`). It serves as the canonical reference for scanner inputs, outputs, data models, error handling, and behavioral semantics.

---

## 1. Scanner Input Specification

The scanner entry point is an asynchronous JavaScript function exported from `src/scanner/index.js` (and re-exported by `src/index.js`):

```javascript
async function scanProject(projectPath)
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
   - Trailing slashes are normalized automatically.
3. **Directory Check**:
   - The resolved path must exist on disk and must be a directory (`stats.isDirectory() === true`).
   - If the path does not exist or points to a file, the scanner returns status `'failed'` with error code `PROJECT_NOT_FOUND`.
4. **Unsupported Package Manager Check**:
   - If alternative package manager lockfiles (`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`) exist in the project root, the scan returns status `'failed'` with error code `UNSUPPORTED_PACKAGE_MANAGER`.

---

## 2. Scanner Output Contract

The scanner returns a JavaScript Promise resolving to a uniform structured object. The result shape is guaranteed to contain all standard keys across all three operational statuses (`'complete'`, `'partial'`, `'failed'`).

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
}
```

### Field Definitions

| Field | Type | Description |
|---|---|---|
| `status` | `'complete' \| 'partial' \| 'failed'` | Overall outcome of the scan. |
| `projectPath` | `string` | Normalized absolute path of the scanned target. |
| `projectMetadata` | `{ name: string, version: string } \| null` | Root package metadata from `package.json`, or `null` if manifest is missing/invalid. |
| `lockfileVersion` | `number \| null` | Detected npm lockfile version (`2` or `3`), or `null` if missing/unparseable. |
| `errors` | `ScanErrorItem[]` | Fatal or blocking issues encountered during the scan. |
| `warnings` | `ScanErrorItem[]` | Non-fatal conditions (e.g. Unresolved optional dependencies, fallback warnings). |
| `components` | `Component[]` | Flat list of all discovered components (root package + all dependencies). |
| `dependencyEdges` | `Record<string, string[]>` | Adjacency list mapping parent component `bomRef` to array of child `bomRef`s. |
| `bom` | `object \| null` | Generated CycloneDX 1.7 JSON SBOM (`null` for `'partial'` and `'failed'` scans). |

---

## 3. Scan Status Semantics

1. **`complete`**:
   - Both `package.json` and a supported `package-lock.json` (v2 or v3) were discovered and parsed.
   - All components, exact resolved versions, integrity hashes, and dependency graph edges were extracted.
   - A valid CycloneDX 1.7 JSON SBOM is populated in `bom`.
   - `errors` array is empty (`[]`).
2. **`partial`**:
   - `package.json` was parsed, but `package-lock.json` is missing, unparseable, or uses an unsupported version (e.g. V1).
   - Direct dependencies declared in `package.json` are returned with version ranges (`version: null`, `versionRange: "^1.0.0"`).
   - Transitive dependencies cannot be reliably resolved and are not fabricated.
   - `bom` is `null` because an incomplete manifest-only scan cannot guarantee exact CycloneDX SBOM integrity.
   - Non-fatal warnings and/or fallback errors explaining the lockfile absence/limitation are populated.
3. **`failed`**:
   - Target path does not exist, is not a directory, or has invalid permissions.
   - `package.json` is missing or contains invalid/unparseable JSON.
   - Unsupported package managers (`yarn.lock`, `pnpm`, `bun`) or unsupported workspace configurations are detected.
   - `components` is empty (`[]`), `dependencyEdges` is empty (`{}`), and `bom` is `null`.

---

## 4. Component Data Model

Each dependency in `components` conforms to the following schema:

```typescript
interface Component {
  name: string;
  version: string | null;
  versionRange?: string;
  ecosystem: 'npm';
  purl: string | null;
  bomRef: string;
  dependencyType: 'root' | 'direct' | 'transitive';
  dependencyGroups: string[];
  integrity: string | null;
  resolved: string | null;
  installPaths: string[];
  optional: boolean;
  dev: boolean;
  devOptional: boolean;
  isRoot?: boolean;
}
```

### Component Field Rules

- **`name`**: Exact npm package name (including scope if applicable, e.g. `@babel/core`).
- **`version`**: Exact resolved semantic version string from lockfile (e.g. `'2.1.3'`). In manifest-only partial scans, `version` is `null`.
- **`versionRange`**: Declared version range from `package.json` (e.g. `'^4.18.0'`), populated during partial scans.
- **`ecosystem`**: Constant string `'npm'`.
- **`purl`**: Standard Package URL format:
  - Standard package: `pkg:npm/ms@2.1.3`
  - Scoped package: `pkg:npm/%40scope/pkg@1.0.0` (scope `@` encoded as `%40`)
  - Manifest-only partial scan: `null` (valid purls require exact resolved versions).
- **`bomRef`**: Unique identifier used across dependency edges and CycloneDX SBOM:
  - Complete scan: Matches `purl`.
  - Manifest-only partial scan: `pkg:npm/<name>@<versionRange>`.
- **`dependencyType`**:
  - `'root'`: The root application being scanned.
  - `'direct'`: Directly declared in root `package.json` and resolved in root graph edges.
  - `'transitive'`: Indirectly required by a parent dependency.
- **`dependencyGroups`**: Array of root declaration groups (`'dependencies'`, `'devDependencies'`, `'optionalDependencies'`, `'peerDependencies'`). Direct dependencies reflect their declared group; transitive dependencies have `[]`.
- **`integrity`**: Subresource integrity hash from lockfile (e.g. `sha512-...` or `sha1-...`), or `null` if unavailable or in partial scans.
- **`resolved`**: Distribution tarball URL from lockfile (e.g. `https://registry.npmjs.org/ms/-/ms-2.1.3.tgz`), or `null` if unavailable or in partial scans. Always `string | null` (never boolean).
- **`installPaths`**: Array of lockfile package paths where this component was resolved (e.g. `['node_modules/ms']`). Empty array `[]` in partial scans.
- **`optional`**: Boolean indicating optional dependency status.
- **`dev`**: Boolean indicating development dependency status.
- **`devOptional`**: Boolean indicating dev-optional status.

---

## 5. Direct vs. Transitive Classification

To prevent version-collision errors where a nested transitive dependency shares a name with a root dependency:

1. The root application (`isRoot: true`) directly links to its resolved dependencies via `dependencyEdges[rootRef]`.
2. A component is classified as **`direct`** if and only if its `bomRef` is present in `dependencyEdges[rootRef]`.
3. If another nested package requires a conflicting version of the same package name (e.g. Root requires `shared@2.0.0`, but child requires `shared@1.0.0`), the nested version is not linked from root and is correctly classified as **`transitive`**.
4. Both versions are retained as distinct components with their respective `bomRef`s.

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
  originalError?: string;
}
```

### Standard Error Codes (`ErrorCodes`)

| Error Code | Severity | Trigger Scenario |
|---|---|---|
| `PROJECT_NOT_FOUND` | Fatal (Failure) | Path does not exist, is not a directory, is empty, or has invalid type. |
| `PROJECT_ACCESS_DENIED` | Fatal (Failure) | Filesystem permission denied on target directory. |
| `PACKAGE_FILE_NOT_FOUND` | Fatal (Failure) / Warning | Fatal when `package.json` missing; warning when `package-lock.json` missing (triggers partial scan). |
| `INVALID_PACKAGE_FILE` | Fatal (Failure) / Fallback | Fatal when `package.json` is malformed JSON; triggers partial scan fallback when `package-lock.json` is malformed. |
| `UNSUPPORTED_LOCKFILE_VERSION` | Fallback | Lockfile version is not 2 or 3 (e.g. Version 1); falls back to partial scan. |
| `UNSUPPORTED_PACKAGE_MANAGER` | Fatal (Failure) | Target contains `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, or `bun.lockb`. |
| `UNSUPPORTED_WORKSPACE_LAYOUT` | Fatal (Failure) / Warning | npm workspaces detected in manifest or symlink links in lockfile. |
| `UNRESOLVED_DEPENDENCY` | Warning | Declared dependency cannot be resolved from the lockfile. |
| `SCAN_ERROR` | Fatal (Failure) | Unexpected runtime error during dependency resolution or SBOM generation. |

---

## 7. Fixture Reference Matrix

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
| `missing-lockfile-project` | Fallback | Valid | None | `partial` | Manifest-only scan; version ranges recorded; `bom: null`. |
| `unsupported-lockfile-project`| Fallback | Valid | v1 | `partial` | Lockfile v1 detected; emits error code and falls back to partial. |
| `invalid-lockfile-project` | Fallback | Valid | Malformed | `partial` | Corrupted lockfile JSON falls back to partial scan. |
| `unresolved-deps-project` | Warning | Valid | Incomplete | `complete` | Unresolved dependency produces `UNRESOLVED_DEPENDENCY` warning. |
| `missing-manifest-project` | Error | None | v3 | `failed` | Fails with `PACKAGE_FILE_NOT_FOUND`. |
| `empty-project` | Error | None | None | `failed` | Fails with `PACKAGE_FILE_NOT_FOUND`. |
| `invalid-project` | Error | Malformed | None | `failed` | Malformed `package.json` fails with `INVALID_PACKAGE_FILE`. |
| `unsupported-project` | Error | Valid | `yarn.lock` | `failed` | Yarn detected; fails with `UNSUPPORTED_PACKAGE_MANAGER`. |

