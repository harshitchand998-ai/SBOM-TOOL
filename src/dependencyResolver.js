import { ErrorCodes, createScanError } from './errors.js';
import { buildDependencyGraph } from './dependencyGraph.js';
import { classifyComponent, isVersionCompatible } from './workspaceDiscovery.js';

/**
 * Normalizes a file path to use forward slashes regardless of platform.
 *
 * @param {string} p - File path to normalize.
 * @returns {string} Path with forward slashes.
 */
function normalizePath(p) {
  return p.replace(/\\/g, '/');
}

/**
 * Extracts the package name from a lockfile key (e.g., "node_modules/express" → "express",
 * "node_modules/express/node_modules/accepts" → "accepts",
 * "node_modules/@scope/pkg" → "@scope/pkg").
 *
 * @param {string} lockfileKey - The key from the packages section of package-lock.json.
 * @returns {string} The extracted package name.
 */
function extractPackageName(lockfileKey) {
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
 * 2. Incorporating discovered first-party workspaces and handling workspace links (link: true).
 * 3. Classifying each package as direct or transitive based on the root project's declarations.
 * 4. Resolving each package's own dependencies to the correct installed version.
 * 5. Handling nested node_modules paths for version conflicts.
 * 6. Tracking dependency groups (dependencies, devDependencies, optionalDependencies, peerDependencies).
 *
 * @param {object} packageJsonData - Parsed package.json data from parser.js.
 * @param {object} lockfileData - Parsed package-lock.json data from parser.js.
 * @param {object} [options={}] - Optional configuration including discovered workspaces.
 * @param {Array<object>} [options.workspaces=[]] - Discovered workspace components.
 * @param {object} [options.rootComponent=null] - Discovered root component.
 * @returns {{
 *   components: Map<string, object>,
 *   dependencyEdges: Map<string, Set<string>>,
 *   rootRef: string,
 *   warnings: Array<object>
 * }}
 */
export function resolveDependencies(packageJsonData, lockfileData, options = {}) {
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
  const rootComp = options.rootComponent;
  const rootRef = rootComp?.bomRef || `pkg:npm/${encodePackageName(packageJsonData.name)}@${packageJsonData.version}`;
  const rootComponentData = {
    name: packageJsonData.name,
    version: packageJsonData.version,
    description: packageJsonData.description || rootComp?.description || '',
    license: packageJsonData.license || rootComp?.license || '',
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
    isFirstParty: true,
    classification: 'first-party',
    origin: 'first-party',
    location: rootComp?.location || { resolved: '', relative: '.' },
    path: rootComp?.path || '',
    relativePath: '.',
  };
  components.set(rootRef, rootComponentData);

  // Setup discovered workspaces
  const workspaces = options.workspaces || [];
  const workspaceByPath = new Map();
  const workspaceByName = new Map();
  const workspaceNames = new Set();

  for (const ws of workspaces) {
    const wsRef = ws.bomRef;
    const wsComp = {
      ...ws,
      ecosystem: 'npm',
      dependencyGroups: directDependencyGroups.get(ws.name) ? [...directDependencyGroups.get(ws.name)] : [],
      integrity: null,
      resolved: null,
      installPaths: [],
      optional: false,
      dev: false,
      devOptional: false,
      isRoot: false,
      isFirstParty: true,
      classification: 'first-party',
      origin: 'first-party',
      dependencyType: 'workspace',
    };
    components.set(wsRef, wsComp);

    workspaceNames.add(ws.name);
    if (!workspaceByName.has(ws.name)) {
      workspaceByName.set(ws.name, wsComp);
    }

    const rel = normalizePath(ws.location?.relative || ws.relativePath || '');
    if (rel) {
      workspaceByPath.set(rel, wsComp);
      workspaceByPath.set(rel.replace(/^\.\//, ''), wsComp);
    }
  }

  // Map from lockfile key to bomRef for resolving dependency edges
  const keyToBomRef = new Map();

  // Step 1: Enumerate all resolved packages and create component entries
  for (const [lockKey, pkgEntry] of Object.entries(packages)) {
    // Skip the root entry (empty string key)
    if (lockKey === '') continue;

    // Check if this lockKey is a discovered workspace package directory
    const normalizedLockKey = normalizePath(lockKey).replace(/^\.\//, '');
    if (workspaceByPath.has(normalizedLockKey)) {
      const wsComp = workspaceByPath.get(normalizedLockKey);
      keyToBomRef.set(lockKey, wsComp.bomRef);
      // Workspace package is already added as first-party; do not duplicate as registry component!
      continue;
    }

    // Handle workspace symlinks (pkgEntry.link: true)
    if (pkgEntry.link) {
      const targetRel = pkgEntry.resolved ? normalizePath(pkgEntry.resolved).replace(/^\.\//, '') : '';
      let targetWs = workspaceByPath.get(targetRel);
      if (!targetWs) {
        const symlinkPkgName = pkgEntry.name || extractPackageName(lockKey);
        targetWs = workspaceByName.get(symlinkPkgName);
      }

      if (targetWs) {
        targetWs.installPaths.push(lockKey);
        keyToBomRef.set(lockKey, targetWs.bomRef);
      } else {
        warnings.push(createScanError(
          ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
          `Linked package detected at "${lockKey}" with target "${pkgEntry.resolved}", which could not be resolved to a known workspace package. Skipping.`,
          { lockfileKey: lockKey, target: pkgEntry.resolved }
        ));
      }
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
    const bomRef = purl;

    // Determine if this is a direct dependency
    const isDirect = directDependencyGroups.has(name);
    const dependencyType = isDirect ? 'direct' : 'transitive';
    const dependencyGroups = isDirect ? [...directDependencyGroups.get(name)] : [];

    // Extract integrity information
    const integrity = pkgEntry.integrity || null;
    const resolved = pkgEntry.resolved || null;

    if (!components.has(bomRef)) {
      const rawComp = {
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
        isFirstParty: false,
        classification: 'third-party',
        origin: 'third-party',
      };
      components.set(bomRef, classifyComponent(rawComp, {
        names: workspaceNames,
        workspaces,
        firstPartyComponents: [rootComponentData, ...workspaces],
      }));
    } else {
      const existing = components.get(bomRef);
      existing.installPaths.push(lockKey);
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
    workspaces,
  });
  const dependencyEdges = graphResult.dependencyEdges;
  warnings.push(...graphResult.warnings);

  // Step 3: Ensure exact direct vs transitive classification based on actual root graph edges
  const directRefs = dependencyEdges.get(rootRef) || new Set();
  for (const [bomRef, comp] of components.entries()) {
    if (comp.isRoot) continue;
    if (comp.dependencyType === 'workspace') {
      if (directRefs.has(bomRef)) {
        comp.dependencyGroups = directDependencyGroups.get(comp.name) || [];
      }
      continue;
    }
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
 * @param {object} [options={}] - Optional configuration including discovered workspaces.
 * @returns {{
 *   components: Map<string, object>,
 *   dependencyEdges: Map<string, Set<string>>,
 *   rootRef: string,
 *   warnings: Array<object>
 * }}
 */
export function resolveManifestOnly(packageJsonData, options = {}) {
  const warnings = [];
  const components = new Map();
  const dependencyEdges = new Map();

  const rootComp = options.rootComponent;
  const rootRef = rootComp?.bomRef || `pkg:npm/${encodePackageName(packageJsonData.name)}@${packageJsonData.version}`;
  components.set(rootRef, {
    name: packageJsonData.name,
    version: packageJsonData.version,
    description: packageJsonData.description || rootComp?.description || '',
    license: packageJsonData.license || rootComp?.license || '',
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
    isFirstParty: true,
    classification: 'first-party',
    origin: 'first-party',
    location: rootComp?.location || { resolved: '', relative: '.' },
    path: rootComp?.path || '',
    relativePath: '.',
  });
  dependencyEdges.set(rootRef, new Set());

  const workspaces = options.workspaces || [];
  const workspaceByName = new Map();
  for (const ws of workspaces) {
    const wsComp = {
      ...ws,
      ecosystem: 'npm',
      dependencyGroups: [],
      integrity: null,
      resolved: null,
      installPaths: [],
      optional: false,
      dev: false,
      devOptional: false,
      isRoot: false,
      isFirstParty: true,
      classification: 'first-party',
      origin: 'first-party',
      dependencyType: 'workspace',
    };
    components.set(ws.bomRef, wsComp);
    dependencyEdges.set(ws.bomRef, new Set());
    if (!workspaceByName.has(ws.name)) {
      workspaceByName.set(ws.name, wsComp);
    }
  }

  const allGroups = [
    ['dependencies', packageJsonData.dependencies],
    ['devDependencies', packageJsonData.devDependencies],
    ['optionalDependencies', packageJsonData.optionalDependencies],
    ['peerDependencies', packageJsonData.peerDependencies],
  ];

  for (const [groupName, deps] of allGroups) {
    if (!deps) continue;
    for (const [name, versionRange] of Object.entries(deps)) {
      if (workspaceByName.has(name)) {
        const ws = workspaceByName.get(name);
        if (isVersionCompatible(ws.version, versionRange)) {
          dependencyEdges.get(rootRef).add(ws.bomRef);
          if (!ws.dependencyGroups.includes(groupName)) {
            ws.dependencyGroups.push(groupName);
          }
        } else {
          warnings.push(createScanError(
            ErrorCodes.UNRESOLVED_DEPENDENCY,
            `Root project declared dependency "${name}" with range "${versionRange}", which is incompatible with local workspace version "${ws.version}". Not linked as workspace dependency.`,
            { workspace: rootComp?.name || packageJsonData.name, dependency: name, declaredRange: versionRange, localVersion: ws.version }
          ));
        }
        continue;
      }

      const bomRef = `pkg:npm/${encodePackageName(name)}@${versionRange}`;
      if (!components.has(bomRef)) {
        components.set(bomRef, {
          name,
          version: null,
          versionRange,
          ecosystem: 'npm',
          purl: null,
          bomRef,
          dependencyType: 'direct',
          dependencyGroups: [groupName],
          integrity: null,
          resolved: null,
          installPaths: [],
          optional: groupName === 'optionalDependencies',
          dev: groupName === 'devDependencies',
          devOptional: false,
          isFirstParty: false,
          classification: 'third-party',
          origin: 'third-party',
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

  // Workspaces declared dependencies
  for (const ws of workspaces) {
    const wsGroups = [
      ['dependencies', ws.dependencies],
      ['devDependencies', ws.devDependencies],
      ['optionalDependencies', ws.optionalDependencies],
      ['peerDependencies', ws.peerDependencies],
    ];

    for (const [groupName, deps] of wsGroups) {
      if (!deps) continue;
      for (const [name, versionRange] of Object.entries(deps)) {
        if (workspaceByName.has(name)) {
          const targetWs = workspaceByName.get(name);
          if (isVersionCompatible(targetWs.version, versionRange)) {
            dependencyEdges.get(ws.bomRef).add(targetWs.bomRef);
          } else {
            warnings.push(createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Workspace "${ws.name}" declared dependency "${name}" with range "${versionRange}", which is incompatible with local workspace version "${targetWs.version}". Not linked as workspace dependency.`,
              { workspace: ws.name, dependency: name, declaredRange: versionRange, localVersion: targetWs.version }
            ));
          }
          continue;
        }

        const bomRef = `pkg:npm/${encodePackageName(name)}@${versionRange}`;
        if (!components.has(bomRef)) {
          components.set(bomRef, {
            name,
            version: null,
            versionRange,
            ecosystem: 'npm',
            purl: null,
            bomRef,
            dependencyType: 'transitive',
            dependencyGroups: [],
            integrity: null,
            resolved: null,
            installPaths: [],
            optional: groupName === 'optionalDependencies',
            dev: groupName === 'devDependencies',
            devOptional: false,
            isFirstParty: false,
            classification: 'third-party',
            origin: 'third-party',
          });
          dependencyEdges.set(bomRef, new Set());
        }
        dependencyEdges.get(ws.bomRef).add(bomRef);
      }
    }
  }

  return { components, dependencyEdges, rootRef, warnings };
}
