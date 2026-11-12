# Anomaly Detection Specification

This document describes the design, validation rules, data contracts, and behavior of the anomaly detection subsystem for `SBOM-TOOL`.

---

## 1. Purpose of Anomaly Detection

An SBOM (Software Bill of Materials) serves as the definitive inventory of an application's software components, packages, and supply chain dependencies. However, generated SBOMs may contain structural defects, missing fields, malformed Package URLs (PURLs), or inconsistent dependency graphs caused by:
- Incomplete manifest files (e.g. missing package versions or names).
- Inconsistent lockfiles or broken local dependency trees.
- Flawed conversion or serialization across package ecosystems.
- Broken graph references (unresolved dependencies or disconnected components).

The anomaly detection module provides a standalone, deterministic analysis engine that inspects CycloneDX SBOMs and component dependency trees to:
- Identify missing and malformed component metadata (names, versions, PURLs, external references).
- Validate package versions against Semantic Versioning (SemVer 2.0.0).
- Validate Package URL (PURL) syntax and verify consistency between PURL attributes and component metadata.
- Validate dependency relationships in the graph (detecting unresolved references, orphan/disconnected components, self-referencing cycles, duplicate edges, and missing root relationships).
- Categorize anomalies by severity (`error`, `warning`, `info`) with actionable remediation recommendations.
- Return structured, deduplicated, and deterministically ordered findings without mutating the input or printing to the terminal.

---

## 2. Input SBOM Structure

The anomaly detector accepts CycloneDX SBOM objects (conforming to CycloneDX 1.4 through 1.7), internal scanner result structures, or component collections:

### 1. CycloneDX SBOM Object (Standard)
```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "purl": "pkg:npm/my-app@1.0.0",
      "bom-ref": "pkg:npm/my-app@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/my-app@1.0.0",
      "dependsOn": [
        "pkg:npm/lodash@4.17.21"
      ]
    },
    {
      "ref": "pkg:npm/lodash@4.17.21",
      "dependsOn": []
    }
  ]
}
```

### 2. Scanner Result Object
Accepts the internal scan result produced by `scanProject()` or `scanProjectSync()`:
- `components`: Array or Map of resolved components (`name`, `version`, `purl`, `bomRef`, `isRoot`, etc.).
- `dependencyEdges`: Map or Object of dependency relationships (`ref -> dependsOn`).

### Fields Inspected
| Field | Location | Required / Inspected | Description |
|---|---|---|---|
| `name` | `component` | Yes | Package identifier (e.g. `express`, `@types/node`). |
| `version` | `component` | Yes | Installed package version string. |
| `purl` | `component` | Recommended | Package URL (e.g. `pkg:npm/lodash@4.17.21`). |
| `bom-ref` / `bomRef` | `component` | Required for graph | Unique identifier matching dependency entries. |
| `externalReferences` | `component` | Recommended (libraries) | Provenance and distribution URLs. |
| `ref` | `dependencies[]` | Yes | Parent component identifier in the graph. |
| `dependsOn` | `dependencies[]` | Yes | Array of child component identifiers. |

---

## 3. Supported Anomaly Types

The engine categorizes anomalies using the `AnomalyType` enumeration:

| Anomaly Type | Default Severity | Description |
|---|---|---|
| `MISSING_NAME` | `error` | Component lacks a valid, non-empty package name string. |
| `MISSING_VERSION` | `warning` | Component lacks an installed version string. |
| `INVALID_VERSION` | `error` | Component version does not conform to SemVer 2.0.0 specification (for `npm` ecosystem). |
| `MISSING_PURL` | `warning` | Component does not define a `purl` attribute. |
| `INVALID_PURL` | `error` | PURL fails syntax validation (invalid scheme, missing type or name). |
| `INCONSISTENT_PURL` | `error` | PURL attributes (package name, version, or ecosystem type) contradict component metadata. |
| `MISSING_REFERENCES` | `info` | Third-party library component lacks external references (e.g. registry distribution URL). |
| `UNRESOLVED_DEPENDENCY` | `error` | A reference in `dependsOn` or `ref` does not correspond to any component in the SBOM. |
| `MISSING_DEPENDENCY_RELATIONSHIP` | `warning` | A component is not connected to the dependency graph (orphan), or root lacks a dependency entry. |
| `INVALID_DEPENDENCY_REFERENCE` | `error` | A dependency entry or child reference is null, empty, non-string, or malformed. |
| `DUPLICATE_BOM_REF` | `error` | Two or more distinct components share the exact same `bom-ref` identifier. |
| `DUPLICATE_DEPENDENCY_EDGE` | `warning` | Duplicate parent entries in `dependencies`, or duplicate child references in `dependsOn`. |
| `SELF_REFERENCING_DEPENDENCY` | `error` | A component declares a dependency relationship directly onto itself in `dependsOn`. |

---

## 4. Component Metadata Validation Rules

1. **Package Name**:
   - Must be a non-null, non-empty string.
   - Whitespace-only strings are rejected as missing names.
   - Violation produces `MISSING_NAME` with `error` severity.

2. **Package Version**:
   - Must be a non-null, non-empty string representing the exact installed version.
   - If missing on library components: produces `MISSING_VERSION` with `warning` severity.
   - Root application components without versions produce `MISSING_VERSION` unless `options.allowRootWithoutVersion: true` is supplied.
   - In the `npm` ecosystem, versions are validated against the strict Semantic Versioning 2.0.0 specification (using the existing SemVer parser from `vulnerabilityMatcher.js`):
     - Valid format: `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`.
     - Permissive normalization: allows optional leading `v` or `=` prefixes (e.g. `v1.2.3`).
     - Malformed versions (e.g. `latest`, `git+https://...`, invalid characters) produce `INVALID_VERSION` with `error` severity.

3. **External References**:
   - Third-party library components (`type: "library"`) are inspected for `externalReferences`.
   - If no references are present: produces `MISSING_REFERENCES` with `info` severity.
   - Can be toggled off via `options.checkReferences: false`.
   - Root application components and workspace packages are not required to contain registry distribution URLs.

4. **BOM References (`bom-ref`)**:
   - Each component must have a unique identifier across the SBOM.
   - Duplicate `bom-ref` collisions across multiple components produce `DUPLICATE_BOM_REF` with `error` severity.

---

## 5. Package URL (PURL) Validation Rules

Package URLs provide a standard identifier across tools and ecosystems. The detector performs three levels of PURL verification:

1. **Existence**:
   - If `purl` is absent or empty: produces `MISSING_PURL` with `warning` severity (can be toggled via `options.requirePurl: false`).
2. **Syntax Conformance**:
   - The string must begin with the `pkg:` scheme.
   - Must contain a valid package type (e.g. `npm`).
   - Must contain a valid name (with optional percent-encoded namespace, e.g. `%40scope/name`).
   - Invalid PURL syntax produces `INVALID_PURL` with `error` severity.
3. **Metadata Consistency**:
   - The detector decomposes the PURL via `parsePurl()` and compares extracted fields against component metadata:
     - **Package Name Consistency**: The PURL name (including decoded namespace) must match `comp.name`. Discrepancies produce `INCONSISTENT_PURL` (`field: "purl.name"`).
     - **Version Consistency**: The PURL version component must match `comp.version`. Discrepancies produce `INCONSISTENT_PURL` (`field: "purl.version"`).
     - **Ecosystem Consistency**: The PURL scheme type must match `comp.ecosystem` (e.g. `npm`). Discrepancies produce `INCONSISTENT_PURL` (`field: "purl.type"`).

---

## 6. Dependency Relationship Validation Rules

The dependency graph in CycloneDX is represented by the `dependencies` array where each element defines `{ ref: string, dependsOn: string[] }`.

1. **Entry Integrity**:
   - Entries in `dependencies` must be objects with valid string `ref` properties and array `dependsOn` lists. Malformed entries produce `INVALID_DEPENDENCY_REFERENCE` with `error` severity.
2. **Referential Integrity (Unresolved References)**:
   - Every parent `ref` must exist in `knownBomRefs` (the root component or components list). Missing parent references produce `UNRESOLVED_DEPENDENCY`.
   - Every child reference in `dependsOn` must exist in `knownBomRefs`. References to absent packages produce `UNRESOLVED_DEPENDENCY` with `error` severity.
3. **Graph Connectivity & Orphans**:
   - Every non-root component should be reachable from or declare relationships within the dependency graph.
   - Components that never appear as a parent `ref` or in any `dependsOn` list produce `MISSING_DEPENDENCY_RELATIONSHIP` with `warning` severity.
   - Root application component must have a parent entry in `dependencies` if dependencies exist in the project; omission produces `MISSING_DEPENDENCY_RELATIONSHIP`.
4. **Self-Referencing Cycles**:
   - A component cannot depend on itself (`dependsOn` containing its own `bom-ref`). Detection produces `SELF_REFERENCING_DEPENDENCY` with `error` severity.
5. **Duplicate Edges**:
   - Duplicate parent entries for the same `ref` produce `DUPLICATE_DEPENDENCY_EDGE` with `warning` severity.
   - Duplicate child references in a single parent's `dependsOn` list produce `DUPLICATE_DEPENDENCY_EDGE` with `warning` severity.

---

## 7. Anomaly Severity Definitions

Anomalies are classified into three severity levels:

- **`error`**:
  Severe data integrity failures that invalidate the SBOM or corrupt dependency resolution.
  - Examples: `MISSING_NAME`, `INVALID_VERSION`, `INVALID_PURL`, `INCONSISTENT_PURL`, `UNRESOLVED_DEPENDENCY`, `DUPLICATE_BOM_REF`, `SELF_REFERENCING_DEPENDENCY`, `INVALID_DEPENDENCY_REFERENCE`.
- **`warning`**:
  Omissions or minor structural issues that degrade SBOM utility or graph completeness but do not invalidate parsing.
  - Examples: `MISSING_VERSION`, `MISSING_PURL`, `MISSING_DEPENDENCY_RELATIONSHIP` (orphans/missing root), `DUPLICATE_DEPENDENCY_EDGE`.
- **`info`**:
  Advisory observations regarding missing optional provenance metadata.
  - Examples: `MISSING_REFERENCES`.

---

## 8. Structured Anomaly Output Schema

Every anomaly record generated conforms to the following schema:

```typescript
interface AnomalyRecord {
  id: string;                     // Sequential deterministic ID (e.g. "ANOMALY-001")
  type: AnomalyType;              // Enum constant identifying the anomaly type
  severity: 'error' | 'warning' | 'info'; // Severity level
  component: {                    // Component snapshot associated with the anomaly
    name: string | null;
    version: string | null;
    purl: string | null;
    bomRef: string | null;
  } | null;
  field?: string;                 // Attribute causing the anomaly (e.g. "version", "purl.name")
  parentRef?: string;             // Parent component ref in relationship anomalies
  dependencyRef?: string;         // Referenced component ref in relationship anomalies
  message: string;                // Human-readable summary of the anomaly
  details: string;                // In-depth explanation of the detection
  recommendation: string;         // Actionable guidance to remediate the defect
  source: string;                 // JSON path or location (e.g. "components[0]", "metadata.component")
}
```

### Summary Object Schema
When requested via `options.summary: true`, `detectAnomalies()` or `summarizeAnomalies()` returns:

```typescript
interface AnomalySummary {
  total: number;
  bySeverity: {
    error: number;
    warning: number;
    info: number;
  };
  byType: Record<string, number>;
}
```

---

## 9. Deduplication Strategy

To prevent noisy, redundant reports when analyzing large SBOMs with multiple overlapping defects:

1. **Deduplication Identity Key**:
   $$\text{Key} = \text{type} + \text{"\:\:"} + \text{componentRef} + \text{"\:\:"} + \text{parentRef} + \text{"\:\:"} + \text{dependencyRef} + \text{"\:\:"} + \text{field}$$
2. **Stable Sorting**:
   Deduplicated anomalies are sorted deterministically using:
   1. `source` path string (`localeCompare`)
   2. Component `bomRef` or `name`
   3. Anomaly `type`
   4. Anomaly `field`
3. **Sequential Identifiers**:
   After sorting, identifiers (`ANOMALY-001`, `ANOMALY-002`, etc.) are assigned sequentially, guaranteeing stable, reproducible test and report outputs.

---

## 10. Unsupported or Optional Metadata Cases

- **Non-npm Ecosystems**: SemVer checks are strictly applied when `comp.ecosystem === 'npm'` or undefined (defaulting to npm). Non-npm components with non-SemVer formats are not penalized with `INVALID_VERSION`.
- **Missing Root Component**: If an SBOM lacks a `metadata.component` section, the detector evaluates the components and dependencies without throwing exceptions.
- **Empty or Null Input**: Passing `null`, `undefined`, or non-object payloads returns an empty array (or empty summary) safely without throwing errors.
- **External References for Root/Workspaces**: Root applications and local workspace packages do not trigger `MISSING_REFERENCES`.

---

## 11. Example SBOM Input

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "sample-service",
      "version": "1.0.0",
      "bom-ref": "pkg:npm/sample-service@1.0.0",
      "purl": "pkg:npm/sample-service@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "broken-pkg",
      "version": "not-a-semver",
      "bom-ref": "pkg:npm/broken-pkg@1.0.0",
      "purl": "pkg:npm/wrong-name@1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/sample-service@1.0.0",
      "dependsOn": [
        "pkg:npm/broken-pkg@1.0.0",
        "pkg:npm/phantom-pkg@2.0.0"
      ]
    },
    {
      "ref": "pkg:npm/broken-pkg@1.0.0",
      "dependsOn": [
        "pkg:npm/broken-pkg@1.0.0"
      ]
    }
  ]
}
```

---

## 12. Example Anomaly Output

```json
[
  {
    "id": "ANOMALY-001",
    "type": "INVALID_VERSION",
    "severity": "error",
    "component": {
      "name": "broken-pkg",
      "version": "not-a-semver",
      "purl": "pkg:npm/wrong-name@1.0.0",
      "bomRef": "pkg:npm/broken-pkg@1.0.0"
    },
    "field": "version",
    "message": "Component version is not a valid semantic version.",
    "details": "The version \"not-a-semver\" for component \"broken-pkg\" does not conform to SemVer 2.0.0 specification.",
    "recommendation": "Ensure the component version follows Semantic Versioning (e.g. X.Y.Z).",
    "source": "components[0]"
  },
  {
    "id": "ANOMALY-002",
    "type": "INCONSISTENT_PURL",
    "severity": "error",
    "component": {
      "name": "broken-pkg",
      "version": "not-a-semver",
      "purl": "pkg:npm/wrong-name@1.0.0",
      "bomRef": "pkg:npm/broken-pkg@1.0.0"
    },
    "field": "purl.name",
    "message": "PURL package name does not match component name.",
    "details": "PURL specifies package name \"wrong-name\" but component metadata declares name \"broken-pkg\".",
    "recommendation": "Update the PURL package name to match the component name.",
    "source": "components[0]"
  },
  {
    "id": "ANOMALY-003",
    "type": "MISSING_REFERENCES",
    "severity": "info",
    "component": {
      "name": "broken-pkg",
      "version": "not-a-semver",
      "purl": "pkg:npm/wrong-name@1.0.0",
      "bomRef": "pkg:npm/broken-pkg@1.0.0"
    },
    "field": "externalReferences",
    "message": "Component lacks external references (e.g. distribution, repository, or advisory links).",
    "details": "Library component \"broken-pkg\" at components[0] has no externalReferences defined.",
    "recommendation": "Include distribution or repository URLs in externalReferences to verify component provenance.",
    "source": "components[0]"
  },
  {
    "id": "ANOMALY-004",
    "type": "SELF_REFERENCING_DEPENDENCY",
    "severity": "error",
    "component": {
      "name": "broken-pkg",
      "version": "not-a-semver",
      "purl": "pkg:npm/wrong-name@1.0.0",
      "bomRef": "pkg:npm/broken-pkg@1.0.0"
    },
    "dependencyRef": "pkg:npm/broken-pkg@1.0.0",
    "parentRef": "pkg:npm/broken-pkg@1.0.0",
    "message": "Component \"pkg:npm/broken-pkg@1.0.0\" declares a self-referencing dependency.",
    "details": "Component ref \"pkg:npm/broken-pkg@1.0.0\" includes itself in its dependsOn array.",
    "recommendation": "Remove self-references from dependsOn arrays.",
    "source": "bom.dependencies[1].dependsOn[0]"
  },
  {
    "id": "ANOMALY-005",
    "type": "UNRESOLVED_DEPENDENCY",
    "severity": "error",
    "component": {
      "name": "phantom-pkg",
      "version": "2.0.0",
      "purl": "pkg:npm/phantom-pkg@2.0.0",
      "bomRef": "pkg:npm/phantom-pkg@2.0.0"
    },
    "dependencyRef": "pkg:npm/phantom-pkg@2.0.0",
    "parentRef": "pkg:npm/sample-service@1.0.0",
    "message": "Unresolved dependency reference: \"pkg:npm/phantom-pkg@2.0.0\" does not exist in SBOM components.",
    "details": "Component \"pkg:npm/sample-service@1.0.0\" declares a dependency on \"pkg:npm/phantom-pkg@2.0.0\", which is not defined in metadata.component or components array.",
    "recommendation": "Ensure all referenced dependencies are resolved and added to the SBOM components.",
    "source": "bom.dependencies[0].dependsOn[1]"
  }
]
```

