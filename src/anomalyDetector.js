/**
 * Anomaly Detector Module
 *
 * Analyzes CycloneDX SBOM components and dependency relationships to identify
 * inconsistencies, missing information, malformed metadata, and graph anomalies.
 */

import { parseSemver } from './vulnerabilityMatcher.js';
import { validatePurl } from './validator.js';

/**
 * Standard anomaly types detected by the module.
 */
export const AnomalyType = Object.freeze({
  MISSING_NAME: 'MISSING_NAME',
  MISSING_VERSION: 'MISSING_VERSION',
  INVALID_VERSION: 'INVALID_VERSION',
  MISSING_PURL: 'MISSING_PURL',
  INVALID_PURL: 'INVALID_PURL',
  INCONSISTENT_PURL: 'INCONSISTENT_PURL',
  MISSING_REFERENCES: 'MISSING_REFERENCES',
  UNRESOLVED_DEPENDENCY: 'UNRESOLVED_DEPENDENCY',
  MISSING_DEPENDENCY_RELATIONSHIP: 'MISSING_DEPENDENCY_RELATIONSHIP',
  INVALID_DEPENDENCY_REFERENCE: 'INVALID_DEPENDENCY_REFERENCE',
  DUPLICATE_BOM_REF: 'DUPLICATE_BOM_REF',
  DUPLICATE_DEPENDENCY_EDGE: 'DUPLICATE_DEPENDENCY_EDGE',
  SELF_REFERENCING_DEPENDENCY: 'SELF_REFERENCING_DEPENDENCY',
});

/**
 * Severity levels for detected anomalies.
 */
export const AnomalySeverity = Object.freeze({
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info',
});

/**
 * Parses a Package URL (PURL) into its constituent components.
 * Reuses validatePurl for syntax conformance and extracts type, namespace,
 * name, version, qualifiers, and subpath.
 *
 * @param {string} purl - The PURL string to parse.
 * @returns {{
 *   type: string,
 *   namespace: string | null,
 *   name: string,
 *   fullName: string,
 *   version: string | null,
 *   qualifiers: string | null,
 *   subpath: string | null
 * } | null} Parsed PURL object or null if invalid.
 */
export function parsePurl(purl) {
  if (typeof purl !== 'string' || purl.trim() === '') {
    return null;
  }

  const validation = validatePurl(purl);
  if (!validation.valid) {
    return null;
  }

  const remainder = purl.substring(4); // Remove 'pkg:'

  // 1. Subpath (#)
  let beforeSubpath = remainder;
  let subpath = null;
  const hashIdx = beforeSubpath.indexOf('#');
  if (hashIdx !== -1) {
    subpath = beforeSubpath.substring(hashIdx + 1);
    beforeSubpath = beforeSubpath.substring(0, hashIdx);
  }

  // 2. Qualifiers (?)
  let beforeQualifiers = beforeSubpath;
  let qualifiers = null;
  const qIdx = beforeQualifiers.indexOf('?');
  if (qIdx !== -1) {
    qualifiers = beforeQualifiers.substring(qIdx + 1);
    beforeQualifiers = beforeQualifiers.substring(0, qIdx);
  }

  // 3. Version (@)
  let beforeVersion = beforeQualifiers;
  let version = null;
  const atIdx = beforeVersion.lastIndexOf('@');
  if (atIdx !== -1) {
    version = beforeVersion.substring(atIdx + 1);
    beforeVersion = beforeVersion.substring(0, atIdx);
  }

  // 4. Type and path components
  const slashIdx = beforeVersion.indexOf('/');
  if (slashIdx === -1) {
    return null;
  }

  const type = beforeVersion.substring(0, slashIdx);
  const pathPart = beforeVersion.substring(slashIdx + 1);

  let namespace = null;
  let name = null;
  const lastSlash = pathPart.lastIndexOf('/');
  if (lastSlash !== -1) {
    namespace = pathPart.substring(0, lastSlash);
    name = pathPart.substring(lastSlash + 1);
  } else {
    name = pathPart;
  }

  const decodedNamespace = namespace ? decodeURIComponent(namespace) : null;
  const decodedName = decodeURIComponent(name);
  const fullName = decodedNamespace ? `${decodedNamespace}/${decodedName}` : decodedName;

  return {
    type: type.toLowerCase(),
    namespace: decodedNamespace,
    name: decodedName,
    fullName,
    version,
    qualifiers,
    subpath,
  };
}

/**
 * Normalizes input SBOM data into uniform components and dependencies arrays.
 * Handles CycloneDX SBOM objects, scanResult objects, or direct component arrays.
 *
 * @param {any} input
 * @returns {{
 *   rootComponent: object | null,
 *   components: Array<object>,
 *   dependencies: Array<object>,
 *   isValidContainer: boolean
 * }}
 */
function normalizeSbomInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {
      rootComponent: null,
      components: [],
      dependencies: [],
      isValidContainer: false,
    };
  }

  // Case 1: CycloneDX BOM object
  if (input.bomFormat === 'CycloneDX' || input.metadata || Array.isArray(input.components)) {
    const rootComponent = input.metadata?.component || null;
    const components = Array.isArray(input.components) ? input.components : [];
    const dependencies = Array.isArray(input.dependencies) ? input.dependencies : [];
    return {
      rootComponent,
      components,
      dependencies,
      isValidContainer: true,
    };
  }

  // Case 2: Internal scanResult object
  if (input.status && (input.components || input.dependencyEdges)) {
    let componentsList = [];
    if (input.components instanceof Map) {
      componentsList = Array.from(input.components.values());
    } else if (Array.isArray(input.components)) {
      componentsList = input.components;
    }

    const rootComp = componentsList.find(c => c && c.isRoot) || null;
    const otherComps = componentsList.filter(c => c && !c.isRoot);

    // Convert dependencyEdges to CycloneDX dependencies format
    const dependenciesList = [];
    if (input.dependencyEdges instanceof Map) {
      for (const [ref, deps] of input.dependencyEdges) {
        dependenciesList.push({ ref, dependsOn: Array.from(deps || []) });
      }
    } else if (input.dependencyEdges && typeof input.dependencyEdges === 'object') {
      for (const [ref, deps] of Object.entries(input.dependencyEdges)) {
        dependenciesList.push({ ref, dependsOn: Array.isArray(deps) ? deps : Array.from(deps || []) });
      }
    }

    return {
      rootComponent: rootComp,
      components: otherComps,
      dependencies: dependenciesList,
      isValidContainer: true,
    };
  }

  return {
    rootComponent: null,
    components: [],
    dependencies: [],
    isValidContainer: false,
  };
}
