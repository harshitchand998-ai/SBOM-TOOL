import { ErrorCodes, createScanError } from './errors.js';

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
  // Dependency edges: bomRef → Set<bomRef>
  const dependencyEdges = new Map();

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
  dependencyEdges.set(rootRef, new Set());

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
      dependencyEdges.set(bomRef, new Set());
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

  // Step 2: Resolve dependency edges using a graph traversal approach
  // For each package, look up its declared dependencies and resolve them
  // to the correct installed package (handling nested node_modules).
  for (const [lockKey, pkgEntry] of Object.entries(packages)) {
    if (lockKey === '') {
      // Root entry — resolve edges from rootRef to its direct dependencies
      const allRootDeps = {
        ...rootDeps,
        ...rootDevDeps,
        ...rootOptDeps,
      };

      // Also include peer dependencies that are resolved
      for (const peerName of Object.keys(rootPeerDeps)) {
        if (!allRootDeps[peerName]) {
          allRootDeps[peerName] = rootPeerDeps[peerName];
        }
      }

      for (const depName of Object.keys(allRootDeps)) {
        const resolvedKey = resolvePackageKey(lockKey, depName, packages);
        if (resolvedKey && keyToBomRef.has(resolvedKey)) {
          dependencyEdges.get(rootRef).add(keyToBomRef.get(resolvedKey));
        } else {
          // Check if this is an optional or peer dependency before warning
          const isOptional = rootOptDeps[depName] !== undefined;
          const isPeer = rootPeerDeps[depName] !== undefined && !rootDeps[depName] && !rootDevDeps[depName];
          if (isPeer) {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Peer dependency "${depName}" declared by root project is not resolved in the lockfile.`,
              { dependency: depName, parent: packageJsonData.name }
            ));
          } else if (isOptional) {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Optional dependency "${depName}" declared by root project is not resolved in the lockfile.`,
              { dependency: depName, parent: packageJsonData.name }
            ));
          } else {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Dependency "${depName}" declared by root project could not be resolved from the lockfile.`,
              { dependency: depName, parent: packageJsonData.name }
            ));
          }
        }
      }
      continue;
    }

    // Skip entries we didn't index (links, versionless)
    if (!keyToBomRef.has(lockKey)) continue;

    const parentBomRef = keyToBomRef.get(lockKey);
    const entryDeps = {
      ...(pkgEntry.dependencies || {}),
      ...(pkgEntry.optionalDependencies || {}),
    };

    // Include resolved peer dependencies
    if (pkgEntry.peerDependencies) {
      for (const [peerName, peerRange] of Object.entries(pkgEntry.peerDependencies)) {
        // Only add if not already in dependencies and if it's not marked as optional peer
        const peerMeta = pkgEntry.peerDependenciesMeta || {};
        const isOptionalPeer = peerMeta[peerName]?.optional === true;
        if (!entryDeps[peerName]) {
          // Try to resolve it — if it resolves, add the edge; if not and it's optional, skip silently
          const resolvedKey = resolvePackageKey(lockKey, peerName, packages);
          if (resolvedKey && keyToBomRef.has(resolvedKey)) {
            entryDeps[peerName] = peerRange;
          } else if (!isOptionalPeer) {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Peer dependency "${peerName}" of "${extractPackageName(lockKey)}" is not resolved in the lockfile.`,
              { dependency: peerName, parent: extractPackageName(lockKey) }
            ));
          }
        }
      }
    }

    for (const depName of Object.keys(entryDeps)) {
      const resolvedKey = resolvePackageKey(lockKey, depName, packages);
      if (resolvedKey && keyToBomRef.has(resolvedKey)) {
        dependencyEdges.get(parentBomRef).add(keyToBomRef.get(resolvedKey));
      } else {
        // Check if this is from optionalDependencies
        const isOptionalDep = pkgEntry.optionalDependencies && pkgEntry.optionalDependencies[depName];
        if (!isOptionalDep) {
          warnings.push(createScanError(
            ErrorCodes.UNRESOLVED_DEPENDENCY,
            `Dependency "${depName}" required by "${extractPackageName(lockKey)}" could not be resolved from the lockfile.`,
            { dependency: depName, parent: extractPackageName(lockKey) }
          ));
        }
      }
    }
  }

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
 * Resolves a dependency name to the correct lockfile key by walking
 * up the node_modules tree from the parent's install path.
 *
 * npm installs dependencies in the nearest node_modules that satisfies the
 * version requirement. When a conflict exists, it nests the dependency under
 * the parent's own node_modules. The lockfile represents this as:
 *   node_modules/parent/node_modules/dep
 *
 * This function searches from the most specific (nested) path outward to
 * the top-level node_modules.
 *
 * @param {string} parentKey - Lockfile key of the parent package.
 * @param {string} depName - Name of the dependency to resolve.
 * @param {object} packages - The packages section from the lockfile.
 * @returns {string|null} The lockfile key of the resolved package, or null if not found.
 */
function resolvePackageKey(parentKey, depName, packages) {
  // For scoped packages, depName is like "@scope/name"
  // For the root (""), the dependency is at "node_modules/<depName>"

  if (parentKey === '') {
    // Root project — dependency is at node_modules/<depName>
    const candidate = `node_modules/${depName}`;
    if (packages[candidate] !== undefined) return candidate;
    return null;
  }

  // For non-root packages, walk up the tree
  // parentKey is like "node_modules/express" or "node_modules/express/node_modules/accepts"
  // First try: parentKey + "/node_modules/" + depName
  let searchBase = parentKey;
  while (true) {
    const candidate = `${searchBase}/node_modules/${depName}`;
    if (packages[candidate] !== undefined) return candidate;

    // Walk up: remove the last "/node_modules/<pkg>" segment
    const lastNM = searchBase.lastIndexOf('/node_modules/');
    if (lastNM === -1) {
      // We've exhausted nested paths — try top-level
      const topLevel = `node_modules/${depName}`;
      if (packages[topLevel] !== undefined) return topLevel;
      return null;
    }
    searchBase = searchBase.substring(0, lastNM);
  }
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
