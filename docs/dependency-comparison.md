# Dependency Comparison Specification

This document describes the component matching strategy, version classification rules, input/output contracts, and limitations of `src/dependencyComparison.js`.

---

## 1. Purpose

`compareInventories(previousBom, currentBom, options)` provides a deterministic, pure (non-mutating, zero-network) comparison between two SBOM inventories to track supply-chain drift across releases:
- Newly introduced packages (**added**)
- Dropped packages (**removed**)
- Upgraded, downgraded, or metadata-modified packages (**changed**)
- Identical packages (**unchanged**)

---

## 2. Public API

Exported from `src/index.js` and `src/dependencyComparison.js`:
- `compareInventories(previousBom, currentBom, options = {})`
- `ComparisonStatus`: `{ COMPLETED: 'completed', FAILED: 'failed' }`
- `ChangeType`: `{ ADDED, REMOVED, UPGRADE, DOWNGRADE, METADATA_CHANGED, VERSION_CHANGED, UNCHANGED }`

### Accepted Input Formats
1. **CycloneDX BOM Objects**: Objects with `bomFormat: 'CycloneDX'`, `metadata`, or a `components` array (`components: []` is valid for empty inventories).
2. **Scanner Result Objects**: Objects returned by `scanProject()` / `scanProjectSync()`. If `bom` is present, its `components` are inspected; otherwise non-root entries in `components` are compared (pass `{ includeRoot: true }` to include root components).

### Input Validation
If either `previousBom` or `currentBom` is `null`, `undefined`, non-object, an Array, an empty `{}` lacking `bomFormat`/`metadata`/`components`, has a non-array `components`, or represents a `'failed'` scan result, `compareInventories()` returns immediately with `status: 'failed'` and structured entries in `errors`.

---

## 3. Component Matching Strategy

To avoid falsely reporting a version upgrade as a removal + addition, components are paired using a **versionless canonical identity**:

1. **Primary Identifier (Valid PURL)**:
   - Parses `comp.purl` via `parsePurl()`.
   - Canonical identity = `<purl.type>:<purl.fullName>` (for example, `npm:@babel/core`, `npm:lodash`).
   - Query qualifiers and subpaths are stripped from the identity key, allowing components to match across URL/qualifier variations while still reporting `purl` metadata changes when versions match.
2. **Fallback Identifier (Missing or Invalid PURL)**:
   - Falls back to `<ecosystem>:<group/name>` or `<ecosystem>:<name>`, setting unspecified `ecosystem` to `'unknown'` (never silently assuming `'npm'`).
   - Emits an `INVALID_PURL` warning if an invalid PURL string was present.
   - If one inventory has an `'unknown:<name>'` bucket and the opposite inventory has a single unambiguous `<ecosystem>:<name>` bucket, they are reconciled automatically; if multiple ecosystems share `<name>`, an `AMBIGUOUS_COMPONENT_MATCH` warning is emitted.
3. **Unresolvable Identity**:
   - If neither a valid PURL nor a non-empty `name` exists, the entry is skipped and an `UNRESOLVABLE_COMPONENT_IDENTITY` warning is emitted.
4. **Multi-Version & Duplicate Buckets**:
   - Components sharing a canonical identity are paired across `previous` and `current` using four passes:
     1. Exact version + identical metadata (preserves unchanged versions first).
     2. Exact version match (detects metadata changes cleanly in multi-version buckets).
     3. Exact `bom-ref` match.
     4. Positional pairing of remaining items in the bucket (upgrades/downgrades).
   - Unpaired `previous` entries are recorded in `removed`; unpaired `current` entries are recorded in `added`.
   - Duplicate `bom-ref` or PURL identifiers within a single inventory emit `DUPLICATE_COMPONENT_IDENTIFIER` warnings without discarding any entry.

---

## 4. Version Comparison & Change Classification

Version comparison reuses `parseSemver()` and `compareSemver()` from `src/vulnerabilityMatcher.js` for npm packages:

| Scenario | Resulting `changeType` | Notes |
|---|---|---|
| Component only in current BOM | `'added'` | Includes current component snapshot & explanation. |
| Component only in previous BOM | `'removed'` | Includes previous component snapshot & explanation. |
| `compareSemver(prev, curr) < 0` | `'upgrade'` | Strictly newer SemVer (e.g. `1.0.0` -> `1.1.0`). |
| `compareSemver(prev, curr) > 0` | `'downgrade'` | Strictly older SemVer (e.g. `2.0.0` -> `1.9.0` or `2.0.0` -> `2.0.0-rc.1`). |
| Versions equal + metadata differs | `'metadata-changed'` | Inspects `purl`, `bomRef`, `type`, `ecosystem`, `isFirstParty`, `hashes`, `externalReferences`, `licenses`, `properties`, `description`, `dependencyType` (order-independent for arrays). |
| Missing or non-SemVer version differs | `'version-changed'` | Emits `NON_COMPARABLE_VERSIONS` warning; never guesses upgrade vs downgrade. |
| Versions and metadata identical | `'unchanged'` | Recorded in `unchanged`. |

---

## 5. Output Structure

```typescript
interface ComparisonResult {
  status: 'completed' | 'failed';
  summary: {
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
  };
  added: Array<{
    identity: string;
    name: string;
    ecosystem: string;
    version: string | null;
    purl: string | null;
    bomRef: string | null;
    changeType: 'added';
    component: ComponentSnapshot;
    explanation: string;
  }>;
  removed: Array<{
    identity: string;
    name: string;
    ecosystem: string;
    version: string | null;
    purl: string | null;
    bomRef: string | null;
    changeType: 'removed';
    component: ComponentSnapshot;
    explanation: string;
  }>;
  changed: Array<{
    identity: string;
    name: string;
    ecosystem: string;
    changeType: 'upgrade' | 'downgrade' | 'metadata-changed' | 'version-changed';
    previousVersion: string | null;
    currentVersion: string | null;
    previousComponent: ComponentSnapshot;
    currentComponent: ComponentSnapshot;
    changedFields: string[];
    explanation: string;
  }>;
  unchanged: Array<{
    identity: string;
    name: string;
    ecosystem: string;
    version: string | null;
    purl: string | null;
    bomRef: string | null;
    component: ComponentSnapshot;
    explanation: string;
  }>;
  errors: Array<{ code: string; target: string; message: string }>;
  warnings: Array<{ code: string; target: string; source: string; message: string }>;
}
```

---

## 6. Known Limitations

1. **Package Renames**: Because identity is keyed by `<ecosystem>:<fullName>`, a package renamed or moved to a different npm scope (e.g. `foo` -> `@org/foo`) is reported as `removed` + `added`.
2. **Non-npm SemVer**: Strict SemVer upgrade/downgrade ordering currently applies to `npm` ecosystem components; non-npm or non-SemVer version changes (such as Git URLs or missing versions) are classified safely as `version-changed` with a warning.
3. **Component-Level Diff**: `compareInventories()` compares component inventories rather than full CycloneDX dependency graph edge topology diffs.

