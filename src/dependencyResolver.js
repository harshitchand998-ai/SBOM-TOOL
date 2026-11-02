import { ErrorCodes, createScanError } from './errors.js';
import { buildDependencyGraph } from './dependencyGraph.js';

/**
 * Extracts the package name from a lockfile key (e.g., "node_modules/express" → "express",
 * "node_modules/express/node_modules/accepts" → "accepts",
 * "node_modules/@scope/pkg" → "@scope/pkg").
 *
 * @param {string} lockfileKey - The key from the packages section of package-lock.json.
 * @returns {string} The extracted package name.
 */
function extractPackageName(lockfileKey) {
  // The package name is after the last "node_modules/" segment.
  // For scoped packages: node_modules/@scope/name → @scope/name
  const nodeModulesPrefix = 'node_modules/';
  const lastIndex = lockfileKey.lastIndexOf(nodeModulesPrefix);
  if (lastIndex === -1) return lockfileKey;
  return lockfileKey.substring(lastIndex + nodeModulesPrefix.length);
}

/**
 * Resolves the dependency tree from parsed package.json and package-lock.json data.
 *
 * This function builds a dependency graph by:
 * 1. Enumerating all resolved packages from the lockfile's packages section.
 * 2. Classifying each package as direct or transitive based on the root project's declarations.
 * 3. Resolving each package's own dependencies to the correct installed version.
 * 4. Handling nested node_modules paths for version conflicts.
 * 5. Tracking dependency groups (dependencies, devDependencies, optionalDependencies, peerDependencies).
 *
 * @param {object} packageJsonData - Parsed package.json data from parser.js.
 * @param {object} lockfileData - Parsed package-lock.json data from parser.js.
 * @returns {{
 *   components: Map<string, object>,
 *   dependencyEdges: Map<string, Set<string>>,
 *   rootRef: string,
 *   warnings: Array<object>
 * }}
 */
export function resolveDependencies(packageJsonData, lockfileData) {
  const warnings = [];
  const packages = lockfileData.packages;

  // Collect all root-level dependency declarations from package.json
  const rootDeps = packageJsonData.dependencies || {};
  const rootDevDeps = packageJsonData.devDependencies || {};
  const rootOptDeps = packageJsonData.optionalDependencies || {};
  const rootPeerDeps = packageJsonData.peerDependencies || {};

  // Build a lookup of all declared direct dependency names → their groups
  const directDependencyGroups = new Map();
  for (const name of Object.keys(rootDeps)) {
    if (!directDependencyGroups.has(name)) directDependencyGroups.set(name, []);
    directDependencyGroups.get(name).push('dependencies');
  }
  for (const name of Object.keys(rootDevDeps)) {
    if (!directDependencyGroups.has(name)) directDependencyGroups.set(name, []);
    directDependencyGroups.get(name).push('devDependencies');
  }
  for (const name of Object.keys(rootOptDeps)) {
    if (!directDependencyGroups.has(name)) directDependencyGroups.set(name, []);
    directDependencyGroups.get(name).push('optionalDependencies');
  }
  for (const name of Object.keys(rootPeerDeps)) {
    if (!directDependencyGroups.has(name)) directDependencyGroups.set(name, []);
    directDependencyGroups.get(name).push('peerDependencies');
  }

  // Components map: bomRef → component data
  const components = new Map();

  // Root application component
  const rootRef = `pkg:npm/${encodePackageName(packageJsonData.name)}@${packageJsonData.version}`;
  components.set(rootRef, {
    name: packageJsonData.name,
    version: packageJsonData.version,
    ecosystem: 'npm',
    purl: rootRef,
    bomRef: rootRef,
    dependencyType: 'root',
    dependencyGroups: [],
    integrity: null,
    resolved: null,
    installPaths: [],
    optional: false,
    dev: false,
    devOptional: false,
    isRoot: true,
  });

  // Map from lockfile key to bomRef for resolving dependency edges
  const keyToBomRef = new Map();

  // Step 1: Enumerate all resolved packages and create component entries
  for (const [lockKey, pkgEntry] of Object.entries(packages)) {
    // Skip the root entry (empty string key)
    if (lockKey === '') continue;

    // Skip link entries (workspace symlinks) — these are unsupported
    if (pkgEntry.link) {
      warnings.push(createScanError(
        ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
        `Linked package detected and skipped: ${lockKey}. Workspace links are not supported in this version.`,
        { lockfileKey: lockKey }
      ));
      continue;
    }

    const name = pkgEntry.name || extractPackageName(lockKey);
    const version = pkgEntry.version;

    if (!version) {
      warnings.push(createScanError(
        ErrorCodes.UNRESOLVED_DEPENDENCY,
        `Package entry "${lockKey}" has no resolved version. Skipping.`,
        { lockfileKey: lockKey, packageName: name }
      ));
      continue;
    }

    const purl = `pkg:npm/${encodePackageName(name)}@${version}`;
    // Use the lockfile key to make bom-refs unique for same name+version at different paths
    const bomRef = purl;

    // Determine if this is a direct dependency
    const isDirect = directDependencyGroups.has(name);
    const dependencyType = isDirect ? 'direct' : 'transitive';
    const dependencyGroups = isDirect ? [...directDependencyGroups.get(name)] : [];

    // Extract integrity information
    const integrity = pkgEntry.integrity || null;
    const resolved = pkgEntry.resolved || null;

    // If component with same bomRef already exists (same name+version at different install path),
    // we just add another keyToBomRef mapping. We deduplicate the component identity.
    if (!components.has(bomRef)) {
      components.set(bomRef, {
        name,
        version,
        ecosystem: 'npm',
        purl,
        bomRef,
        dependencyType,
        dependencyGroups,
        integrity,
        resolved,
        installPaths: [lockKey],
        optional: pkgEntry.optional || false,
        dev: pkgEntry.dev || false,
        devOptional: pkgEntry.devOptional || false,
      });
    } else {
      // Same package+version at a different path — add the install path
      const existing = components.get(bomRef);
      existing.installPaths.push(lockKey);
      // If this path is direct but existing was transitive, upgrade to direct
      if (isDirect && existing.dependencyType === 'transitive') {
        existing.dependencyType = 'direct';
        existing.dependencyGroups = dependencyGroups;
      }
    }

    keyToBomRef.set(lockKey, bomRef);
  }

  // Step 2: Build the dependency graph using the standalone graph builder
  const graphResult = buildDependencyGraph({
    components,
    keyToBomRef,
    packages,
    rootRef,
    rootDeps,
    rootDevDeps,
    rootOptDeps,
    rootPeerDeps,
    rootName: packageJsonData.name,
  });
  const dependencyEdges = graphResult.dependencyEdges;
  warnings.push(...graphResult.warnings);

  // Step 3: Ensure exact direct vs transitive classification based on actual root graph edges
  const directRefs = dependencyEdges.get(rootRef) || new Set();
  for (const [bomRef, comp] of components.entries()) {
    if (comp.isRoot) continue;
    if (directRefs.has(bomRef)) {
      comp.dependencyType = 'direct';
      comp.dependencyGroups = directDependencyGroups.get(comp.name) || [];
    } else {
      comp.dependencyType = 'transitive';
      comp.dependencyGroups = [];
    }
  }

  return { components, dependencyEdges, rootRef, warnings };
}

/**
 * Encodes a package name for use in a Package URL.
 * Scoped packages like @scope/name become %40scope/name.
 *
 * @param {string} name - The npm package name.
 * @returns {string} The encoded package name.
 */
function encodePackageName(name) {
  if (name.startsWith('@')) {
    return '%40' + name.substring(1);
  }
  return name;
}

/**
 * Creates a partial scan result for when only package.json is available
 * (no lockfile). Records version ranges as declarations rather than resolved versions.
 *
 * @param {object} packageJsonData - Parsed package.json data.
 * @returns {{
 *   components: Map<string, object>,
 *   dependencyEdges: Map<string, Set<string>>,
 *   rootRef: string,
 *   warnings: Array<object>
 * }}
 */
export function resolveManifestOnly(packageJsonData) {
  const warnings = [];
  const components = new Map();
  const dependencyEdges = new Map();

  const rootRef = `pkg:npm/${encodePackageName(packageJsonData.name)}@${packageJsonData.version}`;
  components.set(rootRef, {
    name: packageJsonData.name,
    version: packageJsonData.version,
    ecosystem: 'npm',
    purl: rootRef,
    bomRef: rootRef,
    dependencyType: 'root',
    dependencyGroups: [],
    integrity: null,
    resolved: null,
    installPaths: [],
    optional: false,
    dev: false,
    devOptional: false,
    isRoot: true,
  });
  dependencyEdges.set(rootRef, new Set());

  const allGroups = [
    ['dependencies', packageJsonData.dependencies],
    ['devDependencies', packageJsonData.devDependencies],
    ['optionalDependencies', packageJsonData.optionalDependencies],
    ['peerDependencies', packageJsonData.peerDependencies],
  ];

  for (const [groupName, deps] of allGroups) {
    if (!deps) continue;
    for (const [name, versionRange] of Object.entries(deps)) {
      const bomRef = `pkg:npm/${encodePackageName(name)}@${versionRange}`;
      if (!components.has(bomRef)) {
        components.set(bomRef, {
          name,
          version: null,
          versionRange,
          ecosystem: 'npm',
          purl: null, // Cannot produce a valid purl without a resolved version
          bomRef,
          dependencyType: 'direct',
          dependencyGroups: [groupName],
          integrity: null,
          resolved: null,
          installPaths: [],
          optional: groupName === 'optionalDependencies',
          dev: groupName === 'devDependencies',
          devOptional: false,
        });
        dependencyEdges.set(bomRef, new Set());
      } else {
        const existing = components.get(bomRef);
        if (!existing.dependencyGroups.includes(groupName)) {
          existing.dependencyGroups.push(groupName);
        }
      }
      dependencyEdges.get(rootRef).add(bomRef);
    }
  }

  return { components, dependencyEdges, rootRef, warnings };
}
