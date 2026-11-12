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

/**
 * Checks a single component for metadata anomalies.
 *
 * @param {object} comp - Component object.
 * @param {string} source - Location descriptor (e.g. "metadata.component" or "components[0]").
 * @param {object} options - Detector configuration options.
 * @returns {Array<object>} Detected anomaly records for this component.
 */
function checkComponentMetadata(comp, source, options = {}) {
  const anomalies = [];

  if (!comp || typeof comp !== 'object' || Array.isArray(comp)) {
    return anomalies;
  }

  const name = comp.name;
  const version = comp.version;
  const purl = comp.purl;
  const bomRef = comp['bom-ref'] || comp.bomRef || null;
  const isRoot = source.includes('metadata.component') || Boolean(comp.isRoot);

  const baseComponentInfo = {
    name: typeof name === 'string' && name.trim() !== '' ? name.trim() : null,
    version: typeof version === 'string' && version.trim() !== '' ? version.trim() : null,
    purl: typeof purl === 'string' && purl.trim() !== '' ? purl.trim() : null,
    bomRef: typeof bomRef === 'string' && bomRef.trim() !== '' ? bomRef.trim() : null,
  };

  // 1. Missing package name
  if (name === undefined || name === null || typeof name !== 'string' || name.trim() === '') {
    anomalies.push({
      type: AnomalyType.MISSING_NAME,
      severity: AnomalySeverity.ERROR,
      component: { ...baseComponentInfo, name: null },
      field: 'name',
      message: 'Component is missing a package name.',
      details: `The component at ${source} does not contain a valid non-empty name.`,
      recommendation: 'Provide a valid package name in the component metadata.',
      source,
    });
  }

  // 2. Missing or invalid package version
  const hasVersion = version !== undefined && version !== null && typeof version === 'string' && version.trim() !== '';

  if (!hasVersion) {
    // Only flag missing version if not explicitly allowed for root or optional
    const allowRootWithoutVersion = options.allowRootWithoutVersion === true;
    if (!isRoot || !allowRootWithoutVersion) {
      anomalies.push({
        type: AnomalyType.MISSING_VERSION,
        severity: AnomalySeverity.WARNING,
        component: { ...baseComponentInfo, version: null },
        field: 'version',
        message: 'Component is missing version information.',
        details: `The component "${baseComponentInfo.name || 'unnamed'}" at ${source} does not contain an installed version string.`,
        recommendation: 'Specify the exact installed version for the component.',
        source,
      });
    }
  } else {
    // Version is present — check validity
    const trimmedVersion = version.trim();
    const ecosystem = (comp.ecosystem || 'npm').toLowerCase();

    // In npm ecosystem, versions must conform to SemVer 2.0.0
    if (ecosystem === 'npm') {
      const parsed = parseSemver(trimmedVersion);
      if (!parsed) {
        anomalies.push({
          type: AnomalyType.INVALID_VERSION,
          severity: AnomalySeverity.ERROR,
          component: { ...baseComponentInfo, version: trimmedVersion },
          field: 'version',
          message: 'Component version is not a valid semantic version.',
          details: `The version "${trimmedVersion}" for component "${baseComponentInfo.name || 'unnamed'}" does not conform to SemVer 2.0.0 specification.`,
          recommendation: 'Ensure the component version follows Semantic Versioning (e.g. X.Y.Z).',
          source,
        });
      }
    }
  }

  // 3. Missing, invalid, or inconsistent PURL
  const hasPurl = purl !== undefined && purl !== null && typeof purl === 'string' && purl.trim() !== '';

  if (!hasPurl) {
    if (options.requirePurl !== false) {
      anomalies.push({
        type: AnomalyType.MISSING_PURL,
        severity: AnomalySeverity.WARNING,
        component: { ...baseComponentInfo, purl: null },
        field: 'purl',
        message: 'Component is missing a Package URL (PURL).',
        details: `The component "${baseComponentInfo.name || 'unnamed'}" at ${source} does not define a purl attribute.`,
        recommendation: 'Generate a standard Package URL (e.g., pkg:npm/<name>@<version>) for unambiguous identification.',
        source,
      });
    }
  } else {
    const trimmedPurl = purl.trim();
    const parsed = parsePurl(trimmedPurl);

    if (!parsed) {
      anomalies.push({
        type: AnomalyType.INVALID_PURL,
        severity: AnomalySeverity.ERROR,
        component: { ...baseComponentInfo, purl: trimmedPurl },
        field: 'purl',
        message: 'Component contains an invalid or malformed Package URL (PURL).',
        details: `The PURL "${trimmedPurl}" at ${source} does not conform to the Package URL specification.`,
        recommendation: 'Correct the PURL syntax following the pkg:<type>/<namespace>/<name>@<version> format.',
        source,
      });
    } else {
      // PURL is syntactically valid; check consistency with component metadata
      const compName = baseComponentInfo.name;
      const compVer = baseComponentInfo.version;

      // Check name consistency
      if (compName && parsed.fullName !== compName && parsed.name !== compName) {
        anomalies.push({
          type: AnomalyType.INCONSISTENT_PURL,
          severity: AnomalySeverity.ERROR,
          component: { ...baseComponentInfo, purl: trimmedPurl },
          field: 'purl.name',
          message: 'PURL package name does not match component name.',
          details: `PURL specifies package name "${parsed.fullName}" but component metadata declares name "${compName}".`,
          recommendation: 'Update the PURL package name to match the component name.',
          source,
        });
      }

      // Check version consistency
      if (compVer && parsed.version && parsed.version !== compVer) {
        anomalies.push({
          type: AnomalyType.INCONSISTENT_PURL,
          severity: AnomalySeverity.ERROR,
          component: { ...baseComponentInfo, purl: trimmedPurl },
          field: 'purl.version',
          message: 'PURL version does not match component version.',
          details: `PURL specifies version "${parsed.version}" but component metadata declares version "${compVer}".`,
          recommendation: 'Update the PURL version to match the installed component version.',
          source,
        });
      }

      // Check ecosystem consistency (e.g. npm)
      const expectedEcosystem = (comp.ecosystem || 'npm').toLowerCase();
      if (expectedEcosystem && parsed.type !== expectedEcosystem) {
        anomalies.push({
          type: AnomalyType.INCONSISTENT_PURL,
          severity: AnomalySeverity.ERROR,
          component: { ...baseComponentInfo, purl: trimmedPurl },
          field: 'purl.type',
          message: 'PURL package type does not match expected component ecosystem.',
          details: `PURL specifies type "${parsed.type}" but component belongs to ecosystem "${expectedEcosystem}".`,
          recommendation: `Set the PURL scheme type to "pkg:${expectedEcosystem}/...".`,
          source,
        });
      }
    }
  }

  // 4. Missing external references
  // Third-party library components in npm SBOMs are expected to specify external references (e.g. distribution url).
  if (options.checkReferences !== false && !isRoot && comp.type === 'library') {
    const hasRefs = Array.isArray(comp.externalReferences) && comp.externalReferences.length > 0;
    if (!hasRefs) {
      anomalies.push({
        type: AnomalyType.MISSING_REFERENCES,
        severity: AnomalySeverity.INFO,
        component: { ...baseComponentInfo },
        field: 'externalReferences',
        message: 'Component lacks external references (e.g. distribution, repository, or advisory links).',
        details: `Library component "${baseComponentInfo.name || 'unnamed'}" at ${source} has no externalReferences defined.`,
        recommendation: 'Include distribution or repository URLs in externalReferences to verify component provenance.',
        source,
      });
    }
  }

  return anomalies;
}

/**
 * Checks the CycloneDX dependency relationships for graph consistency,
 * unresolved references, missing relationships, and self-references.
 *
 * @param {Array<object>} dependencies - The dependencies array from the BOM.
 * @param {Set<string>} knownBomRefs - Set of all known component bom-refs in the SBOM.
 * @param {string | null} rootBomRef - bom-ref of the root component.
 * @param {Map<string, object>} componentByRef - Map of bom-ref to component metadata.
 * @param {object} options - Detector options.
 * @returns {Array<object>} Array of detected relationship anomalies.
 */
function checkDependencyRelationships(dependencies, knownBomRefs, rootBomRef, componentByRef, options = {}) {
  const anomalies = [];

  if (!Array.isArray(dependencies)) {
    return anomalies;
  }

  const seenParentRefs = new Set();
  const referencedAsChild = new Set();
  let hasRootEntry = false;

  for (let i = 0; i < dependencies.length; i++) {
    const dep = dependencies[i];
    const source = `bom.dependencies[${i}]`;

    if (!dep || typeof dep !== 'object' || Array.isArray(dep)) {
      anomalies.push({
        type: AnomalyType.INVALID_DEPENDENCY_REFERENCE,
        severity: AnomalySeverity.ERROR,
        component: null,
        message: 'Dependency entry must be a valid non-null object.',
        details: `Entry at ${source} is not a valid object.`,
        recommendation: 'Ensure all entries in bom.dependencies are objects with "ref" and "dependsOn" fields.',
        source,
      });
      continue;
    }

    const parentRef = dep.ref;

    // Check parent ref validity
    if (parentRef === undefined || parentRef === null || typeof parentRef !== 'string' || parentRef.trim() === '') {
      anomalies.push({
        type: AnomalyType.INVALID_DEPENDENCY_REFERENCE,
        severity: AnomalySeverity.ERROR,
        component: null,
        dependencyRef: null,
        parentRef: null,
        message: 'Dependency entry is missing a valid "ref" identifier.',
        details: `The dependency entry at ${source} has an empty or invalid "ref" property.`,
        recommendation: 'Specify a valid component bom-ref in the "ref" field.',
        source,
      });
    } else {
      const trimmedParentRef = parentRef.trim();

      // Check for duplicate parent dependency entries
      if (seenParentRefs.has(trimmedParentRef)) {
        anomalies.push({
          type: AnomalyType.DUPLICATE_DEPENDENCY_EDGE,
          severity: AnomalySeverity.WARNING,
          component: componentByRef.get(trimmedParentRef) || { bomRef: trimmedParentRef },
          dependencyRef: trimmedParentRef,
          parentRef: trimmedParentRef,
          message: `Duplicate dependency entry detected for ref "${trimmedParentRef}".`,
          details: `Multiple entries define dependency relationships for component ref "${trimmedParentRef}".`,
          recommendation: 'Consolidate multiple dependency entries for the same component into a single entry.',
          source,
        });
      } else {
        seenParentRefs.add(trimmedParentRef);
      }

      if (rootBomRef && trimmedParentRef === rootBomRef) {
        hasRootEntry = true;
      }

      // Check if parent ref resolves to a known component
      if (!knownBomRefs.has(trimmedParentRef)) {
        anomalies.push({
          type: AnomalyType.UNRESOLVED_DEPENDENCY,
          severity: AnomalySeverity.ERROR,
          component: { bomRef: trimmedParentRef },
          dependencyRef: trimmedParentRef,
          parentRef: trimmedParentRef,
          message: 'Dependency entry references a component identifier not present in the SBOM.',
          details: `The dependency ref "${trimmedParentRef}" at ${source} does not match any component in metadata or components.`,
          recommendation: 'Ensure all components defined in dependency relationships exist in the SBOM.',
          source,
        });
      }

      // Check dependsOn array
      if (!Array.isArray(dep.dependsOn)) {
        anomalies.push({
          type: AnomalyType.INVALID_DEPENDENCY_REFERENCE,
          severity: AnomalySeverity.ERROR,
          component: componentByRef.get(trimmedParentRef) || { bomRef: trimmedParentRef },
          dependencyRef: null,
          parentRef: trimmedParentRef,
          message: 'Dependency entry "dependsOn" must be an array of component references.',
          details: `The entry at ${source} for ref "${trimmedParentRef}" has a non-array "dependsOn" field.`,
          recommendation: 'Define dependsOn as an array of child component bom-refs.',
          source,
        });
      } else {
        const seenChildrenInEntry = new Set();

        for (let j = 0; j < dep.dependsOn.length; j++) {
          const childRef = dep.dependsOn[j];
          const childSource = `${source}.dependsOn[${j}]`;

          if (childRef === undefined || childRef === null || typeof childRef !== 'string' || childRef.trim() === '') {
            anomalies.push({
              type: AnomalyType.INVALID_DEPENDENCY_REFERENCE,
              severity: AnomalySeverity.ERROR,
              component: componentByRef.get(trimmedParentRef) || { bomRef: trimmedParentRef },
              dependencyRef: null,
              parentRef: trimmedParentRef,
              message: 'Invalid child dependency reference in dependsOn array.',
              details: `The child reference at ${childSource} is empty, null, or not a string.`,
              recommendation: 'Ensure all child references in dependsOn are valid strings.',
              source: childSource,
            });
            continue;
          }

          const trimmedChild = childRef.trim();

          // Check for self-referencing dependency
          if (trimmedChild === trimmedParentRef) {
            anomalies.push({
              type: AnomalyType.SELF_REFERENCING_DEPENDENCY,
              severity: AnomalySeverity.ERROR,
              component: componentByRef.get(trimmedParentRef) || { bomRef: trimmedParentRef },
              dependencyRef: trimmedChild,
              parentRef: trimmedParentRef,
              message: `Component "${trimmedParentRef}" declares a self-referencing dependency.`,
              details: `Component ref "${trimmedParentRef}" includes itself in its dependsOn array.`,
              recommendation: 'Remove self-references from dependsOn arrays.',
              source: childSource,
            });
          }

          // Check for duplicate child references within the same parent
          if (seenChildrenInEntry.has(trimmedChild)) {
            anomalies.push({
              type: AnomalyType.DUPLICATE_DEPENDENCY_EDGE,
              severity: AnomalySeverity.WARNING,
              component: componentByRef.get(trimmedParentRef) || { bomRef: trimmedParentRef },
              dependencyRef: trimmedChild,
              parentRef: trimmedParentRef,
              message: `Duplicate child reference "${trimmedChild}" in dependsOn for "${trimmedParentRef}".`,
              details: `The child reference "${trimmedChild}" appears more than once in the dependsOn list of "${trimmedParentRef}".`,
              recommendation: 'Deduplicate child references in dependsOn arrays.',
              source: childSource,
            });
          } else {
            seenChildrenInEntry.add(trimmedChild);
          }

          referencedAsChild.add(trimmedChild);

          // Check if child ref resolves to a known component
          if (!knownBomRefs.has(trimmedChild)) {
            // Attempt to extract package name and version from purl if applicable
            const parsedChildPurl = parsePurl(trimmedChild);
            anomalies.push({
              type: AnomalyType.UNRESOLVED_DEPENDENCY,
              severity: AnomalySeverity.ERROR,
              component: {
                name: parsedChildPurl?.fullName || null,
                version: parsedChildPurl?.version || null,
                purl: trimmedChild.startsWith('pkg:') ? trimmedChild : null,
                bomRef: trimmedChild,
              },
              dependencyRef: trimmedChild,
              parentRef: trimmedParentRef,
              message: `Unresolved dependency reference: "${trimmedChild}" does not exist in SBOM components.`,
              details: `Component "${trimmedParentRef}" declares a dependency on "${trimmedChild}", which is not defined in metadata.component or components array.`,
              recommendation: 'Ensure all referenced dependencies are resolved and added to the SBOM components.',
              source: childSource,
            });
          }
        }
      }
    }
  }

  // Check if root component entry is missing when components exist
  if (rootBomRef && !hasRootEntry && (dependencies.length > 0 || knownBomRefs.size > 1)) {
    anomalies.push({
      type: AnomalyType.MISSING_DEPENDENCY_RELATIONSHIP,
      severity: AnomalySeverity.WARNING,
      component: componentByRef.get(rootBomRef) || { bomRef: rootBomRef },
      dependencyRef: rootBomRef,
      parentRef: rootBomRef,
      message: `Root application component "${rootBomRef}" lacks an entry in bom.dependencies.`,
      details: 'The root component has no defined dependency relationships in the SBOM dependencies array.',
      recommendation: 'Add a dependency entry for the root component specifying its direct dependencies.',
      source: 'bom.dependencies',
    });
  }

  // Check for orphan / disconnected components (neither root, nor declared in dependencies, nor reachable as child)
  for (const [ref, comp] of componentByRef.entries()) {
    if (ref === rootBomRef) continue;
    if (!seenParentRefs.has(ref) && !referencedAsChild.has(ref)) {
      anomalies.push({
        type: AnomalyType.MISSING_DEPENDENCY_RELATIONSHIP,
        severity: AnomalySeverity.WARNING,
        component: comp,
        dependencyRef: ref,
        message: `Component "${comp.name || ref}" has no dependency relationships in the graph.`,
        details: `The component with bom-ref "${ref}" does not appear as a parent entry or as a child in any dependsOn array.`,
        recommendation: 'Connect the component to its parent dependency in bom.dependencies or verify whether it is an orphan package.',
        source: 'bom.dependencies',
      });
    }
  }

  return anomalies;
}

/**
 * Deduplicates anomaly records based on a stable identity key:
 * type + component.bomRef + parentRef + dependencyRef + field
 *
 * @param {Array<object>} anomalies - Raw list of anomaly records.
 * @returns {Array<object>} Deduplicated and deterministically sorted anomaly records.
 */
function deduplicateAnomalies(anomalies) {
  const map = new Map();

  for (const a of anomalies) {
    if (!a || typeof a !== 'object') continue;

    const compRef = a.component?.bomRef || a.component?.name || '';
    const parentRef = a.parentRef || '';
    const depRef = a.dependencyRef || '';
    const field = a.field || '';

    const key = `${a.type}::${compRef}::${parentRef}::${depRef}::${field}`;

    if (!map.has(key)) {
      map.set(key, { ...a });
    }
  }

  const list = Array.from(map.values());

  // Deterministic sort: source -> component name / ref -> type -> field
  list.sort((a, b) => {
    const srcComp = (a.source || '').localeCompare(b.source || '');
    if (srcComp !== 0) return srcComp;

    const refA = a.component?.bomRef || a.component?.name || '';
    const refB = b.component?.bomRef || b.component?.name || '';
    const refComp = refA.localeCompare(refB);
    if (refComp !== 0) return refComp;

    const typeComp = (a.type || '').localeCompare(b.type || '');
    if (typeComp !== 0) return typeComp;

    return (a.field || '').localeCompare(b.field || '');
  });

  // Assign sequential deterministic anomaly IDs (e.g. ANOMALY-001)
  return list.map((item, index) => {
    const id = `ANOMALY-${String(index + 1).padStart(3, '0')}`;
    return {
      id,
      ...item,
    };
  });
}

/**
 * Computes a summary of anomalies grouped by severity and type.
 *
 * @param {Array<object>} anomalies - List of detected anomaly records.
 * @returns {{
 *   total: number,
 *   bySeverity: { error: number, warning: number, info: number },
 *   byType: Record<string, number>
 * }}
 */
export function summarizeAnomalies(anomalies) {
  const summary = {
    total: 0,
    bySeverity: {
      [AnomalySeverity.ERROR]: 0,
      [AnomalySeverity.WARNING]: 0,
      [AnomalySeverity.INFO]: 0,
    },
    byType: {},
  };

  if (!Array.isArray(anomalies)) {
    return summary;
  }

  for (const a of anomalies) {
    if (!a || typeof a !== 'object') continue;
    summary.total++;

    if (a.severity && summary.bySeverity[a.severity] !== undefined) {
      summary.bySeverity[a.severity]++;
    }

    if (a.type) {
      summary.byType[a.type] = (summary.byType[a.type] || 0) + 1;
    }
  }

  return summary;
}

/**
 * Detects anomalies in a CycloneDX SBOM or internal component structure.
 * Inspects component metadata, Package URLs, external references, and dependency
 * relationships to return structured, deduplicated anomaly records.
 *
 * Does not mutate the input SBOM, make network requests, or print to the terminal.
 *
 * @param {object} sbom - The CycloneDX SBOM or component container object.
 * @param {object} [options={}] - Optional detector configuration.
 * @param {boolean} [options.requirePurl=true] - Whether missing PURLs are flagged as anomalies.
 * @param {boolean} [options.checkReferences=true] - Whether missing external references are checked.
 * @param {boolean} [options.allowRootWithoutVersion=false] - Whether root application without version is tolerated.
 * @param {boolean} [options.summary=false] - Whether to return an object with anomalies and summary.
 * @returns {Array<object> | { anomalies: Array<object>, summary: object }}
 */
export function detectAnomalies(sbom, options = {}) {
  const rawAnomalies = [];

  const { rootComponent, components, dependencies, isValidContainer } = normalizeSbomInput(sbom);

  if (!isValidContainer) {
    // Malformed or null container
    const emptyResult = [];
    if (options.summary === true) {
      return { anomalies: emptyResult, summary: summarizeAnomalies(emptyResult) };
    }
    return emptyResult;
  }

  const knownBomRefs = new Set();
  const componentByRef = new Map();
  let rootBomRef = null;

  // 1. Process and check root component
  if (rootComponent && typeof rootComponent === 'object' && !Array.isArray(rootComponent)) {
    const rootRef = rootComponent['bom-ref'] || rootComponent.bomRef;
    if (rootRef && typeof rootRef === 'string') {
      rootBomRef = rootRef.trim();
      knownBomRefs.add(rootBomRef);
      componentByRef.set(rootBomRef, {
        name: rootComponent.name || null,
        version: rootComponent.version || null,
        purl: rootComponent.purl || null,
        bomRef: rootBomRef,
        isRoot: true,
      });
    }

    const rootAnomalies = checkComponentMetadata(rootComponent, 'metadata.component', {
      ...options,
      checkReferences: false, // Root applications are not expected to have distribution urls
    });
    rawAnomalies.push(...rootAnomalies);
  }

  // 2. Process and check library components
  for (let i = 0; i < components.length; i++) {
    const comp = components[i];
    const source = `components[${i}]`;

    if (!comp || typeof comp !== 'object' || Array.isArray(comp)) {
      continue;
    }

    const compRef = comp['bom-ref'] || comp.bomRef;
    if (compRef && typeof compRef === 'string') {
      const trimmedRef = compRef.trim();

      // Check for duplicate bom-ref collisions
      if (knownBomRefs.has(trimmedRef)) {
        rawAnomalies.push({
          type: AnomalyType.DUPLICATE_BOM_REF,
          severity: AnomalySeverity.ERROR,
          component: {
            name: comp.name || null,
            version: comp.version || null,
            purl: comp.purl || null,
            bomRef: trimmedRef,
          },
          field: 'bom-ref',
          message: `Duplicate component bom-ref: "${trimmedRef}".`,
          details: `The bom-ref "${trimmedRef}" at ${source} collides with another component in the SBOM.`,
          recommendation: 'Ensure every component in the SBOM has a unique bom-ref.',
          source,
        });
      } else {
        knownBomRefs.add(trimmedRef);
        componentByRef.set(trimmedRef, {
          name: comp.name || null,
          version: comp.version || null,
          purl: comp.purl || null,
          bomRef: trimmedRef,
          isRoot: false,
        });
      }
    }

    const compAnomalies = checkComponentMetadata(comp, source, options);
    rawAnomalies.push(...compAnomalies);
  }

  // 3. Process and check dependency relationships
  const graphAnomalies = checkDependencyRelationships(dependencies, knownBomRefs, rootBomRef, componentByRef, options);
  rawAnomalies.push(...graphAnomalies);

  // 4. Deduplicate and order anomalies
  const deduplicated = deduplicateAnomalies(rawAnomalies);

  if (options.summary === true) {
    return {
      anomalies: deduplicated,
      summary: summarizeAnomalies(deduplicated),
    };
  }

  return deduplicated;
}

export default detectAnomalies;
