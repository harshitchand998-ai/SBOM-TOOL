import { ErrorCodes, createScanError } from './errors.js';

/**
 * Extracts the package name from a lockfile key.
 * E.g., "node_modules/express/node_modules/accepts" → "accepts"
 *
 * @param {string} lockfileKey
 * @returns {string}
 */
function extractPackageName(lockfileKey) {
  const prefix = 'node_modules/';
  const lastIndex = lockfileKey.lastIndexOf(prefix);
  if (lastIndex === -1) return lockfileKey;
  return lockfileKey.substring(lastIndex + prefix.length);
}

/**
 * Resolves a dependency name to the correct lockfile key by walking
 * up the node_modules tree from the parent's install path.
 *
 * @param {string} parentKey - Lockfile key of the parent package.
 * @param {string} depName - Name of the dependency to resolve.
 * @param {object} packages - The packages section from the lockfile.
 * @returns {string|null}
 */
function resolvePackageKey(parentKey, depName, packages) {
  if (parentKey === '') {
    const candidate = `node_modules/${depName}`;
    return packages[candidate] !== undefined ? candidate : null;
  }

  let searchBase = parentKey;
  while (true) {
    const candidate = `${searchBase}/node_modules/${depName}`;
    if (packages[candidate] !== undefined) return candidate;

    const lastNM = searchBase.lastIndexOf('/node_modules/');
    if (lastNM === -1) {
      const topLevel = `node_modules/${depName}`;
      return packages[topLevel] !== undefined ? topLevel : null;
    }
    searchBase = searchBase.substring(0, lastNM);
  }
}

/**
 * Builds a dependency graph (adjacency list) from resolved components
 * and lockfile package data.
 *
 * @param {object} options
 * @param {Map<string, object>} options.components - bomRef → component data.
 * @param {Map<string, string>} options.keyToBomRef - lockfile key → bomRef.
 * @param {object} options.packages - The lockfile packages section.
 * @param {string} options.rootRef - The root component's bomRef.
 * @param {object} options.rootDeps - Root dependencies from package.json.
 * @param {object} options.rootDevDeps - Root devDependencies.
 * @param {object} options.rootOptDeps - Root optionalDependencies.
 * @param {object} options.rootPeerDeps - Root peerDependencies.
 * @param {string} options.rootName - Root project name.
 * @returns {{ dependencyEdges: Map<string, Set<string>>, warnings: object[] }}
 */
export function buildDependencyGraph({
  components,
  keyToBomRef,
  packages,
  rootRef,
  rootDeps,
  rootDevDeps,
  rootOptDeps,
  rootPeerDeps,
  rootName,
}) {
  const warnings = [];
  const dependencyEdges = new Map();

  // Initialize edges for all components
  for (const bomRef of components.keys()) {
    dependencyEdges.set(bomRef, new Set());
  }

  for (const [lockKey, pkgEntry] of Object.entries(packages)) {
    if (lockKey === '') {
      // Root entry — resolve edges from rootRef to its direct dependencies
      const allRootDeps = {
        ...rootDeps,
        ...rootDevDeps,
        ...rootOptDeps,
      };

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
          const isOptional = rootOptDeps[depName] !== undefined;
          const isPeer = rootPeerDeps[depName] !== undefined && !rootDeps[depName] && !rootDevDeps[depName];
          if (isPeer) {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Peer dependency "${depName}" declared by root project is not resolved in the lockfile.`,
              { dependency: depName, parent: rootName }
            ));
          } else if (isOptional) {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Optional dependency "${depName}" declared by root project is not resolved in the lockfile.`,
              { dependency: depName, parent: rootName }
            ));
          } else {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Dependency "${depName}" declared by root project could not be resolved from the lockfile.`,
              { dependency: depName, parent: rootName }
            ));
          }
        }
      }
      continue;
    }

    // Skip entries we didn't index
    if (!keyToBomRef.has(lockKey)) continue;

    const parentBomRef = keyToBomRef.get(lockKey);
    const entryDeps = {
      ...(pkgEntry.dependencies || {}),
      ...(pkgEntry.optionalDependencies || {}),
    };

    if (pkgEntry.peerDependencies) {
      for (const [peerName, peerRange] of Object.entries(pkgEntry.peerDependencies)) {
        const peerMeta = pkgEntry.peerDependenciesMeta || {};
        const isOptionalPeer = peerMeta[peerName]?.optional === true;
        if (!entryDeps[peerName]) {
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

  return { dependencyEdges, warnings };
}
