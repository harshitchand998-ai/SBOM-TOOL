import fs from 'node:fs';
import path from 'node:path';
import { ErrorCodes, ScanStatus, createScanError } from './errors.js';
import { parsePackageJson } from './parser.js';

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
 * Encodes an npm package name for use in Package URLs (purl) and bomRef.
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
 * Parses a semantic version string into major, minor, patch numbers.
 *
 * @param {string} v - Version string (e.g., "1.2.3", "v1.2.3").
 * @returns {{ major: number, minor: number, patch: number } | null}
 */
function parseSemver(v) {
  if (typeof v !== 'string') return null;
  const clean = v.trim().replace(/^[=v]/, '');
  const match = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: match[2] !== undefined ? parseInt(match[2], 10) : 0,
    patch: match[3] !== undefined ? parseInt(match[3], 10) : 0,
  };
}

/**
 * Compares two parsed semver versions.
 *
 * @param {{ major: number, minor: number, patch: number }} v1
 * @param {{ major: number, minor: number, patch: number }} v2
 * @returns {number} Negative if v1 < v2, 0 if v1 === v2, positive if v1 > v2.
 */
function compareSemver(v1, v2) {
  if (v1.major !== v2.major) return v1.major - v2.major;
  if (v1.minor !== v2.minor) return v1.minor - v2.minor;
  if (v1.patch !== v2.patch) return v1.patch - v2.patch;
  return 0;
}

/**
 * Tests if a local package version satisfies a single comparator clause.
 *
 * @param {{ major: number, minor: number, patch: number }} local
 * @param {string} clause - Single comparator clause (e.g., "^1.0.0", ">=1.0.0").
 * @returns {boolean}
 */
function satisfiesSingleClause(local, clause) {
  let c = clause.trim();
  if (c === '' || c === '*' || c === 'latest' || c === 'x' || c === 'X') {
    return true;
  }
  if (c.startsWith('workspace:')) {
    c = c.substring('workspace:'.length).trim();
    if (c === '' || c === '*' || c === '^' || c === '~') {
      return true;
    }
  }
  if (c.startsWith('file:') || c.startsWith('link:')) {
    return true;
  }

  if (c.startsWith('^')) {
    const target = parseSemver(c.substring(1));
    if (!target) return false;
    if (compareSemver(local, target) < 0) return false;
    if (target.major > 0) {
      return local.major === target.major;
    }
    if (target.minor > 0) {
      return local.major === 0 && local.minor === target.minor;
    }
    return local.major === 0 && local.minor === 0 && local.patch === target.patch;
  }

  if (c.startsWith('~')) {
    const target = parseSemver(c.substring(1));
    if (!target) return false;
    if (compareSemver(local, target) < 0) return false;
    return local.major === target.major && local.minor === target.minor;
  }

  if (c.startsWith('>=')) {
    const target = parseSemver(c.substring(2));
    return target ? compareSemver(local, target) >= 0 : false;
  }
  if (c.startsWith('>')) {
    const target = parseSemver(c.substring(1));
    return target ? compareSemver(local, target) > 0 : false;
  }
  if (c.startsWith('<=')) {
    const target = parseSemver(c.substring(2));
    return target ? compareSemver(local, target) <= 0 : false;
  }
  if (c.startsWith('<')) {
    const target = parseSemver(c.substring(1));
    return target ? compareSemver(local, target) < 0 : false;
  }

  const target = parseSemver(c);
  if (!target) return false;
  return compareSemver(local, target) === 0;
}

/**
 * Checks whether a local workspace version satisfies a declared version range.
 *
 * @param {string} localVersion - Concrete installed local version.
 * @param {string} declaredRange - Declared range in package.json (e.g. "^1.0.0", "workspace:*").
 * @returns {boolean} True if compatible, false otherwise.
 */
export function isVersionCompatible(localVersion, declaredRange) {
  if (typeof declaredRange !== 'string' || declaredRange.trim() === '') {
    return true;
  }
  const local = parseSemver(localVersion);
  if (!local) return false;

  const range = declaredRange.trim();
  if (range.includes('||')) {
    return range.split('||').some(part => isVersionCompatible(localVersion, part.trim()));
  }

  const clauses = range.split(/\s+/).filter(Boolean);
  return clauses.every(c => satisfiesSingleClause(local, c));
}

/**
 * Validates and extracts an array of workspace pattern strings from the raw workspaces field.
 * Supports both array format: ["packages/*"] and object format: { packages: ["packages/*"] }.
 *
 * @param {any} workspacesField - The raw workspaces field from package.json.
 * @returns {{ patterns: string[] | null, error: string | null }}
 */
function extractWorkspacePatterns(workspacesField) {
  if (workspacesField === undefined || workspacesField === null) {
    return { patterns: [], error: null };
  }

  let rawList = null;

  if (Array.isArray(workspacesField)) {
    rawList = workspacesField;
  } else if (
    typeof workspacesField === 'object' &&
    workspacesField !== null &&
    !Array.isArray(workspacesField)
  ) {
    if (Array.isArray(workspacesField.packages)) {
      rawList = workspacesField.packages;
    } else {
      return {
        patterns: null,
        error: 'Workspace object configuration must contain a "packages" array.',
      };
    }
  } else {
    return {
      patterns: null,
      error: 'Workspace configuration must be an array of pattern strings or an object with a "packages" array.',
    };
  }

  for (let i = 0; i < rawList.length; i++) {
    const item = rawList[i];
    if (typeof item !== 'string' || item.trim() === '') {
      return {
        patterns: null,
        error: `Workspace pattern at index ${i} must be a non-empty string.`,
      };
    }
  }

  return { patterns: rawList, error: null };
}

/**
 * Converts a glob pattern string to a RegExp matching relative paths.
 * Supports *, **, ?, and literal segments.
 *
 * @param {string} pattern - Glob pattern.
 * @returns {RegExp} Compiled regular expression.
 */
function globToRegex(pattern) {
  let clean = pattern.replace(/^[!]/, '').trim();
  if (clean.startsWith('./')) clean = clean.substring(2);
  while (clean.endsWith('/')) clean = clean.substring(0, clean.length - 1);

  let regexStr = '^';
  let i = 0;
  while (i < clean.length) {
    if (clean.substring(i, i + 2) === '**') {
      if (clean[i + 2] === '/') {
        regexStr += '(?:.+/)?';
        i += 3;
      } else {
        regexStr += '.*';
        i += 2;
      }
    } else if (clean[i] === '*') {
      regexStr += '[^/]*';
      i++;
    } else if (clean[i] === '?') {
      regexStr += '[^/]';
      i++;
    } else {
      const ch = clean[i];
      if (/[-[\]{}()+.,\\^$|#\s]/.test(ch)) {
        regexStr += '\\' + ch;
      } else {
        regexStr += ch;
      }
      i++;
    }
  }
  regexStr += '$';
  return new RegExp(regexStr);
}

/**
 * Checks if a glob or path pattern attempts to escape the project root directory.
 *
 * @param {string} projectRoot - Root project path.
 * @param {string} pattern - Workspace pattern.
 * @param {string} [canonicalRoot=projectRoot] - Canonical resolved root path.
 * @returns {boolean} True if pattern escapes project root.
 */
function patternEscapesRoot(projectRoot, pattern, canonicalRoot = projectRoot) {
  const clean = pattern.replace(/^[!]/, '').trim();
  const normalized = normalizePath(clean);
  if (normalized.startsWith('../') || normalized === '..') {
    return true;
  }
  if (path.isAbsolute(clean)) {
    const rel1 = path.relative(projectRoot, clean);
    const rel2 = path.relative(canonicalRoot, clean);
    if ((rel1.startsWith('..') || path.isAbsolute(rel1)) && (rel2.startsWith('..') || path.isAbsolute(rel2))) {
      return true;
    }
  }
  return false;
}

/**
 * Determines whether a Dirent entry is a directory or a symlink to a directory.
 *
 * @param {string} parentDir - Directory containing the entry.
 * @param {fs.Dirent} entry - Dirent entry.
 * @returns {boolean}
 */
function isDirectoryEntry(parentDir, entry) {
  if (entry.name === 'node_modules' || entry.name.startsWith('.')) return false;
  if (entry.isDirectory()) return true;
  if (entry.isSymbolicLink()) {
    try {
      return fs.statSync(path.join(parentDir, entry.name)).isDirectory();
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Recursively resolves pattern segments against the filesystem to find matching directories.
 * Strictly excludes node_modules and hidden directories.
 *
 * @param {string} currentDir - Currently inspected directory.
 * @param {number} segmentIndex - Index in the parts array.
 * @param {string[]} parts - Split pattern segments.
 * @param {string} projectRoot - Root project directory.
 * @param {string[]} matchedDirs - Output array for matched directory paths.
 * @param {Set<string>} visitedPaths - Set of visited canonical paths to avoid cycles.
 * @param {boolean} isRecursiveWildcard - True if matched via **.
 */
function matchSegments(
  currentDir,
  segmentIndex,
  parts,
  projectRoot,
  matchedDirs,
  visitedPaths = new Set(),
  isRecursiveWildcard = false
) {
  // If we have consumed all segments
  if (segmentIndex >= parts.length) {
    if (currentDir !== projectRoot) {
      try {
        const stat = fs.statSync(currentDir);
        if (stat.isDirectory()) {
          // If discovered via **, only add if it contains package.json to avoid intermediate directories
          if (isRecursiveWildcard) {
            if (fs.existsSync(path.join(currentDir, 'package.json'))) {
              matchedDirs.push(currentDir);
            }
          } else {
            matchedDirs.push(currentDir);
          }
        }
      } catch {
        matchedDirs.push(currentDir);
      }
    }
    return;
  }

  let realCurrent;
  try {
    realCurrent = fs.realpathSync(currentDir);
  } catch {
    return;
  }

  // Prevent circular traversal
  const visitedKey = `${realCurrent}:${segmentIndex}`;
  if (visitedPaths.has(visitedKey)) {
    return;
  }
  visitedPaths.add(visitedKey);

  const segment = parts[segmentIndex];

  if (segment === '**') {
    // 0 segments match: continue with next segment in current directory
    matchSegments(
      currentDir,
      segmentIndex + 1,
      parts,
      projectRoot,
      matchedDirs,
      new Set(visitedPaths),
      true
    );

    // If ** is the terminal segment, and currentDir itself has a package.json and is not projectRoot, it's also a candidate
    if (
      segmentIndex + 1 >= parts.length &&
      currentDir !== projectRoot &&
      fs.existsSync(path.join(currentDir, 'package.json'))
    ) {
      matchedDirs.push(currentDir);
    }

    // Traverse subdirectories recursively
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (isDirectoryEntry(currentDir, entry)) {
          const subDir = path.join(currentDir, entry.name);
          matchSegments(
            subDir,
            segmentIndex,
            parts,
            projectRoot,
            matchedDirs,
            new Set(visitedPaths),
            true
          );
        }
      }
    } catch {
      // Inaccessible directory
    }
  } else if (segment.includes('*') || segment.includes('?')) {
    // Glob wildcard segment
    const regexStr =
      '^' +
      segment
        .replace(/[-[\]{}()+.,\\^$|#\s]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$';
    const regex = new RegExp(regexStr);

    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (regex.test(entry.name) && isDirectoryEntry(currentDir, entry)) {
          const subDir = path.join(currentDir, entry.name);
          matchSegments(
            subDir,
            segmentIndex + 1,
            parts,
            projectRoot,
            matchedDirs,
            new Set(visitedPaths),
            isRecursiveWildcard
          );
        }
      }
    } catch {
      // Inaccessible directory
    }
  } else {
    // Literal directory segment
    if (segment === 'node_modules') return;

    const subDir = path.join(currentDir, segment);
    try {
      if (fs.existsSync(subDir)) {
        const stat = fs.statSync(subDir);
        if (stat.isDirectory()) {
          matchSegments(
            subDir,
            segmentIndex + 1,
            parts,
            projectRoot,
            matchedDirs,
            new Set(visitedPaths),
            isRecursiveWildcard
          );
        }
      }
    } catch {
      // Inaccessible directory
    }
  }
}

/**
 * Resolves workspace glob patterns into unique directory paths.
 * Supports positive patterns, negated patterns (!path), and wildcards (*, **, ?).
 *
 * @param {string} projectRoot - Absolute path to the project root.
 * @param {string[]} patterns - Array of workspace glob patterns.
 * @param {string} [canonicalRoot=projectRoot] - Canonical project root path.
 * @returns {{
 *   directories: string[],
 *   emptyPatterns: string[],
 *   missingLiteralPaths: string[],
 *   escapingPatterns: string[]
 * }}
 */
function resolveWorkspaceDirectories(projectRoot, patterns, canonicalRoot = projectRoot) {
  const allMatched = [];
  const emptyPatterns = [];
  const missingLiteralPaths = [];
  const escapingPatterns = [];

  const positivePatterns = [];
  const negativePatterns = [];

  for (const rawPattern of patterns) {
    if (typeof rawPattern !== 'string') continue;
    const trimmed = normalizePath(rawPattern.trim());
    if (patternEscapesRoot(projectRoot, trimmed, canonicalRoot)) {
      escapingPatterns.push(rawPattern.trim());
      continue;
    }
    if (trimmed.startsWith('!')) {
      negativePatterns.push(trimmed.substring(1).trim());
    } else {
      positivePatterns.push(trimmed);
    }
  }

  for (const rawPattern of positivePatterns) {
    let clean = normalizePath(rawPattern.trim());
    if (clean.startsWith('./')) clean = clean.substring(2);
    while (clean.endsWith('/')) clean = clean.substring(0, clean.length - 1);

    const isLiteral = !clean.includes('*') && !clean.includes('?');
    if (isLiteral) {
      const literalPath = path.resolve(projectRoot, clean);
      if (!fs.existsSync(literalPath)) {
        missingLiteralPaths.push(clean);
        continue;
      }
      try {
        const stat = fs.statSync(literalPath);
        if (!stat.isDirectory()) {
          missingLiteralPaths.push(clean);
          continue;
        }
      } catch {
        missingLiteralPaths.push(clean);
        continue;
      }
    }

    const parts = clean.split('/').filter(Boolean);
    const patternMatches = [];
    matchSegments(projectRoot, 0, parts, projectRoot, patternMatches, new Set());

    if (patternMatches.length === 0) {
      emptyPatterns.push(rawPattern);
    } else {
      allMatched.push(...patternMatches);
    }
  }

  // Deduplicate and filter out negated patterns
  const compiledNegatives = negativePatterns.map(neg => globToRegex(neg));
  const seenPaths = new Set();
  const directories = [];

  for (const dir of allMatched) {
    const resolved = path.resolve(dir);
    const relFromRoot = normalizePath(path.relative(projectRoot, resolved));

    // Exclude if matched by any negative pattern
    const isExcluded = compiledNegatives.some(regex => regex.test(relFromRoot));
    if (isExcluded) {
      continue;
    }

    if (!seenPaths.has(resolved)) {
      seenPaths.add(resolved);
      directories.push(resolved);
    }
  }

  return { directories, emptyPatterns, missingLiteralPaths, escapingPatterns };
}

/**
 * Classifies a single component as first-party or third-party based on discovered first-party package
 * names, local workspace locations, and lockfile/installation metadata.
 *
 * External package instances (e.g. from registry or external node_modules) are never classified as
 * local workspaces even if their name matches a workspace name.
 *
 * @param {object} component - The component to classify.
 * @param {Set<string> | string[] | object} firstPartyContext - Set or Array of first-party package names, or discovery context.
 * @returns {object} The component with classification and isFirstParty flags.
 */
export function classifyComponent(component, firstPartyContext) {
  if (!component || typeof component !== 'object') {
    return component;
  }

  let names;
  let workspaceMap = null;

  if (firstPartyContext instanceof Set) {
    names = firstPartyContext;
  } else if (Array.isArray(firstPartyContext)) {
    names = new Set(firstPartyContext);
  } else if (firstPartyContext && typeof firstPartyContext === 'object') {
    if (firstPartyContext.names instanceof Set) {
      names = firstPartyContext.names;
    } else if (Array.isArray(firstPartyContext.names)) {
      names = new Set(firstPartyContext.names);
    } else if (Array.isArray(firstPartyContext.firstPartyComponents)) {
      names = new Set(firstPartyContext.firstPartyComponents.map(c => c.name));
    } else {
      names = new Set();
    }
    if (Array.isArray(firstPartyContext.workspaces)) {
      workspaceMap = new Map();
      for (const ws of firstPartyContext.workspaces) {
        workspaceMap.set(ws.name, ws);
      }
    }
  } else {
    names = new Set();
  }

  // 1. Root application is always first-party
  if (component.isRoot === true) {
    return {
      ...component,
      isFirstParty: true,
      classification: 'first-party',
      origin: 'first-party',
    };
  }

  // 2. Local workspace components are first-party
  if (component.dependencyType === 'workspace') {
    return {
      ...component,
      isFirstParty: true,
      classification: 'first-party',
      origin: 'first-party',
    };
  }

  // 3. If name is not a discovered first-party package name, it is definitely third-party
  if (!names.has(component.name)) {
    return {
      ...component,
      isFirstParty: false,
      classification: 'third-party',
      origin: 'third-party',
    };
  }

  // 4. Name matches a first-party component. Verify installation-path and lockfile-link metadata:
  // Check if component has lockfile-link or resolved information
  const hasRemoteResolved =
    typeof component.resolved === 'string' &&
    /^(https?:\/\/|git(\+[a-z]+)?:\/\/|ssh:\/\/|npm:)/i.test(component.resolved);

  const hasRegistryIntegrity =
    typeof component.integrity === 'string' &&
    component.integrity.trim().length > 0 &&
    component.link !== true;

  const isExplicitNonLink = component.link === false;

  const hasOnlyNodeModulesInstallPaths =
    Array.isArray(component.installPaths) &&
    component.installPaths.length > 0 &&
    component.installPaths.every(p => normalizePath(p).includes('node_modules/'));

  // If the package instance was downloaded from a remote registry or has registry integrity
  // and is in node_modules, it is an external package instance, not the local workspace!
  if (hasRemoteResolved || hasRegistryIntegrity || (isExplicitNonLink && hasOnlyNodeModulesInstallPaths)) {
    return {
      ...component,
      isFirstParty: false,
      classification: 'third-party',
      origin: 'third-party',
    };
  }

  // If workspace version information is available and this component version does not match
  if (workspaceMap && workspaceMap.has(component.name)) {
    const localWs = workspaceMap.get(component.name);
    if (component.version && localWs.version && component.version !== localWs.version) {
      if (hasOnlyNodeModulesInstallPaths || hasRemoteResolved) {
        return {
          ...component,
          isFirstParty: false,
          classification: 'third-party',
          origin: 'third-party',
        };
      }
    }
  }

  // If component.link === true or has local workspace location, it's first-party
  return {
    ...component,
    isFirstParty: true,
    classification: 'first-party',
    origin: 'first-party',
  };
}

/**
 * Classifies an array of components as first-party or third-party.
 *
 * @param {object[]} components - Array of components.
 * @param {Set<string> | string[] | object} firstPartyContext - First-party context.
 * @returns {object[]} Array of classified components.
 */
export function classifyComponents(components, firstPartyContext) {
  if (!Array.isArray(components)) {
    return [];
  }
  return components.map(c => classifyComponent(c, firstPartyContext));
}

/**
 * Synchronously discovers the root application and all local npm workspace packages in a project.
 *
 * @param {string} projectPath - Target project directory path.
 * @param {object} [options={}] - Optional configuration options.
 * @param {object[]} [options.components] - Optional array of components to classify.
 * @returns {{
 *   status: string,
 *   projectPath: string,
 *   root: object | null,
 *   workspaces: object[],
 *   firstPartyComponents: object[],
 *   workspaceDependencies: Record<string, string[]>,
 *   dependencyEdges: Record<string, string[]>,
 *   classifiedComponents?: object[],
 *   errors: object[],
 *   warnings: object[]
 * }}
 */
export function discoverFirstPartyComponentsSync(projectPath, options = {}) {
  const errors = [];
  const warnings = [];

  // 1. Path validation
  if (typeof projectPath !== 'string' || projectPath.trim() === '') {
    errors.push(
      createScanError(
        ErrorCodes.PROJECT_NOT_FOUND,
        `Project path must be a non-empty string, received: ${JSON.stringify(projectPath)}`,
        { path: projectPath }
      )
    );
    return {
      status: ScanStatus.FAILED,
      projectPath: typeof projectPath === 'string' ? projectPath : '',
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  const resolvedRootPath = path.resolve(projectPath);

  if (!fs.existsSync(resolvedRootPath)) {
    errors.push(
      createScanError(
        ErrorCodes.PROJECT_NOT_FOUND,
        `Project directory does not exist: ${resolvedRootPath}`,
        { path: resolvedRootPath }
      )
    );
    return {
      status: ScanStatus.FAILED,
      projectPath: resolvedRootPath,
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  let stats;
  try {
    stats = fs.statSync(resolvedRootPath);
  } catch (err) {
    errors.push(
      createScanError(
        ErrorCodes.PROJECT_ACCESS_DENIED,
        `Cannot access project directory: ${resolvedRootPath}`,
        { path: resolvedRootPath, originalError: err.message }
      )
    );
    return {
      status: ScanStatus.FAILED,
      projectPath: resolvedRootPath,
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  if (!stats.isDirectory()) {
    errors.push(
      createScanError(
        ErrorCodes.PROJECT_NOT_FOUND,
        `Supplied path is not a directory: ${resolvedRootPath}`,
        { path: resolvedRootPath }
      )
    );
    return {
      status: ScanStatus.FAILED,
      projectPath: resolvedRootPath,
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  let canonicalRootPath = resolvedRootPath;
  try {
    canonicalRootPath = fs.realpathSync(resolvedRootPath);
  } catch {
    // Keep resolvedRootPath
  }

  // 2. Locate and parse root package.json
  const rootPkgPath = path.join(resolvedRootPath, 'package.json');
  if (!fs.existsSync(rootPkgPath)) {
    errors.push(
      createScanError(
        ErrorCodes.PACKAGE_FILE_NOT_FOUND,
        `package.json not found in the project directory: ${resolvedRootPath}`,
        { path: resolvedRootPath, file: 'package.json' }
      )
    );
    return {
      status: ScanStatus.FAILED,
      projectPath: resolvedRootPath,
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  const rootParsedResult = parsePackageJson(rootPkgPath);
  errors.push(...rootParsedResult.errors);
  warnings.push(...rootParsedResult.warnings);

  if (rootParsedResult.errors.length > 0 || !rootParsedResult.data) {
    return {
      status: ScanStatus.FAILED,
      projectPath: resolvedRootPath,
      root: null,
      workspaces: [],
      firstPartyComponents: [],
      workspaceDependencies: {},
      dependencyEdges: {},
      errors,
      warnings,
    };
  }

  const rootData = rootParsedResult.data;
  const rootPurl = `pkg:npm/${encodePackageName(rootData.name)}@${rootData.version}`;

  const rootComponent = {
    name: rootData.name,
    version: rootData.version,
    description: rootData.description || '',
    license: rootData.license || '',
    location: {
      resolved: resolvedRootPath,
      relative: '.',
    },
    path: resolvedRootPath,
    relativePath: '.',
    workspaces: rootData.workspaces,
    isFirstParty: true,
    classification: 'first-party',
    origin: 'first-party',
    dependencyType: 'root',
    isRoot: true,
    purl: rootPurl,
    bomRef: rootPurl,
    dependencies: { ...rootData.dependencies },
    devDependencies: { ...rootData.devDependencies },
    optionalDependencies: { ...rootData.optionalDependencies },
    peerDependencies: { ...rootData.peerDependencies },
    workspaceDependencies: [],
  };

  // 3. Workspace resolution
  const workspaces = [];
  const seenWorkspaceNames = new Map(); // name -> relative location
  const usedBomRefs = new Set([rootComponent.bomRef]);

  if (rootData.workspaces !== null && rootData.workspaces !== undefined) {
    const { patterns, error: configError } = extractWorkspacePatterns(rootData.workspaces);

    if (configError) {
      errors.push(
        createScanError(
          ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
          `Invalid workspace configuration in root package.json: ${configError}`,
          { file: 'package.json', originalError: configError }
        )
      );
      return {
        status: ScanStatus.FAILED,
        projectPath: resolvedRootPath,
        root: rootComponent,
        workspaces: [],
        firstPartyComponents: [rootComponent],
        workspaceDependencies: { [rootComponent.name]: [] },
        dependencyEdges: { [rootComponent.bomRef]: [] },
        errors,
        warnings,
      };
    }

    if (patterns.length > 0) {
      const { directories, emptyPatterns, missingLiteralPaths, escapingPatterns } =
        resolveWorkspaceDirectories(resolvedRootPath, patterns, canonicalRootPath);

      // Report patterns that escape the project root
      for (const escapingPattern of escapingPatterns) {
        errors.push(
          createScanError(
            ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
            `Workspace pattern "${escapingPattern}" escapes project root.`,
            { pattern: escapingPattern }
          )
        );
      }

      // Report missing literal workspace directories
      for (const missingPath of missingLiteralPaths) {
        errors.push(
          createScanError(
            ErrorCodes.PACKAGE_FILE_NOT_FOUND,
            `Workspace directory does not exist: ${missingPath}`,
            { path: path.resolve(resolvedRootPath, missingPath), pattern: missingPath }
          )
        );
      }

      // Report patterns that matched no packages
      for (const emptyPattern of emptyPatterns) {
        warnings.push(
          createScanError(
            ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
            `Workspace pattern "${emptyPattern}" matched no packages.`,
            { pattern: emptyPattern }
          )
        );
      }

      // Read each discovered workspace directory
      for (const wsDir of directories) {
        const wsPkgPath = path.join(wsDir, 'package.json');
        const relativeLoc = normalizePath(path.relative(resolvedRootPath, wsDir));

        // Validate that workspace directory path does not escape the project root (e.g. symlinks)
        let realWsDir;
        try {
          realWsDir = fs.realpathSync(wsDir);
        } catch (err) {
          errors.push(
            createScanError(
              ErrorCodes.PACKAGE_FILE_NOT_FOUND,
              `Workspace directory could not be resolved: ${relativeLoc}`,
              { path: wsDir, relativePath: relativeLoc, originalError: err.message }
            )
          );
          continue;
        }

        const relToCanonical = path.relative(canonicalRootPath, realWsDir);
        const relToResolved = path.relative(resolvedRootPath, realWsDir);
        const escapesCanonical = relToCanonical.startsWith('..') || path.isAbsolute(relToCanonical);
        const escapesResolved = relToResolved.startsWith('..') || path.isAbsolute(relToResolved);

        if (escapesCanonical && escapesResolved) {
          errors.push(
            createScanError(
              ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
              `Workspace directory "${relativeLoc}" resolves outside project root: "${realWsDir}". Workspaces escaping project root are not supported.`,
              { path: wsDir, realPath: realWsDir, relativePath: relativeLoc }
            )
          );
          continue;
        }

        if (!fs.existsSync(wsPkgPath)) {
          errors.push(
            createScanError(
              ErrorCodes.PACKAGE_FILE_NOT_FOUND,
              `package.json not found in workspace directory: ${relativeLoc}`,
              { path: wsDir, file: 'package.json', relativePath: relativeLoc }
            )
          );
          continue;
        }

        const wsParsedResult = parsePackageJson(wsPkgPath);
        errors.push(...wsParsedResult.errors);
        warnings.push(...wsParsedResult.warnings);

        if (wsParsedResult.errors.length > 0 || !wsParsedResult.data) {
          continue;
        }

        const wsData = wsParsedResult.data;

        // Check for workspace package name collision with root application
        if (wsData.name === rootComponent.name) {
          errors.push(
            createScanError(
              ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
              `Workspace package at "${relativeLoc}" has the same name "${wsData.name}" as the root project.`,
              { packageName: wsData.name, relativePath: relativeLoc, isRootConflict: true }
            )
          );
        }

        // Check for duplicate workspace package names
        if (seenWorkspaceNames.has(wsData.name)) {
          const firstLoc = seenWorkspaceNames.get(wsData.name);
          errors.push(
            createScanError(
              ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
              `Duplicate workspace package name "${wsData.name}" detected at "${relativeLoc}" (already defined at "${firstLoc}").`,
              { packageName: wsData.name, firstPath: firstLoc, duplicatePath: relativeLoc }
            )
          );
        } else {
          seenWorkspaceNames.set(wsData.name, relativeLoc);
        }

        const basePurl = `pkg:npm/${encodePackageName(wsData.name)}@${wsData.version}`;
        // Ensure unambiguous bomRef even in the presence of duplicate package names or root collisions
        let uniqueBomRef = basePurl;
        if (usedBomRefs.has(uniqueBomRef)) {
          uniqueBomRef = `${basePurl}#${relativeLoc}`;
        }
        usedBomRefs.add(uniqueBomRef);

        workspaces.push({
          name: wsData.name,
          version: wsData.version,
          description: wsData.description || '',
          license: wsData.license || '',
          location: {
            resolved: wsDir,
            relative: relativeLoc,
          },
          path: wsDir,
          relativePath: relativeLoc,
          isFirstParty: true,
          classification: 'first-party',
          origin: 'first-party',
          dependencyType: 'workspace',
          purl: basePurl,
          bomRef: uniqueBomRef,
          dependencies: { ...wsData.dependencies },
          devDependencies: { ...wsData.devDependencies },
          optionalDependencies: { ...wsData.optionalDependencies },
          peerDependencies: { ...wsData.peerDependencies },
          workspaceDependencies: [],
        });
      }
    }
  }

  // 4. Resolve workspace dependency relationships
  // Create mapping of workspace name -> workspace component
  const workspaceMap = new Map();
  const duplicateWorkspaceNames = new Set();
  for (const ws of workspaces) {
    if (!workspaceMap.has(ws.name)) {
      workspaceMap.set(ws.name, ws);
    } else {
      duplicateWorkspaceNames.add(ws.name);
    }
  }

  // Mapping from package name to bomRef (for uniquely disambiguating graph edges)
  const nameToBomRef = new Map();
  nameToBomRef.set(rootComponent.name, rootComponent.bomRef);
  for (const ws of workspaces) {
    if (!nameToBomRef.has(ws.name)) {
      nameToBomRef.set(ws.name, ws.bomRef);
    }
  }

  // Helper to extract declared range from component's dependency groups
  const getDeclaredRange = (comp, depName) => {
    return (
      (comp.dependencies && comp.dependencies[depName]) ||
      (comp.devDependencies && comp.devDependencies[depName]) ||
      (comp.optionalDependencies && comp.optionalDependencies[depName]) ||
      (comp.peerDependencies && comp.peerDependencies[depName]) ||
      '*'
    );
  };

  // Resolve root's dependencies on workspaces
  const rootAllDeps = new Set([
    ...Object.keys(rootComponent.dependencies || {}),
    ...Object.keys(rootComponent.devDependencies || {}),
    ...Object.keys(rootComponent.optionalDependencies || {}),
    ...Object.keys(rootComponent.peerDependencies || {}),
  ]);
  const rootWsDeps = [];
  for (const depName of rootAllDeps) {
    if (duplicateWorkspaceNames.has(depName)) {
      warnings.push(
        createScanError(
          ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
          `Dependency "${depName}" declared by "${rootComponent.name}" cannot be resolved because multiple local workspaces share this package name. Relationship is ambiguous and skipped.`,
          {
            workspace: rootComponent.name,
            dependency: depName,
          }
        )
      );
      continue;
    }
    if (workspaceMap.has(depName)) {
      const targetWs = workspaceMap.get(depName);
      const declaredRange = getDeclaredRange(rootComponent, depName);
      if (isVersionCompatible(targetWs.version, declaredRange)) {
        rootWsDeps.push(depName);
      } else {
        warnings.push(
          createScanError(
            ErrorCodes.UNRESOLVED_DEPENDENCY,
            `Root project declared dependency "${depName}" with range "${declaredRange}", which is incompatible with local workspace version "${targetWs.version}". Not linked as workspace dependency.`,
            {
              workspace: rootComponent.name,
              dependency: depName,
              declaredRange,
              localVersion: targetWs.version,
            }
          )
        );
      }
    }
  }
  rootComponent.workspaceDependencies = rootWsDeps.sort();

  // Resolve each workspace's dependencies on other workspaces
  for (const ws of workspaces) {
    const wsAllDeps = new Set([
      ...Object.keys(ws.dependencies || {}),
      ...Object.keys(ws.devDependencies || {}),
      ...Object.keys(ws.optionalDependencies || {}),
      ...Object.keys(ws.peerDependencies || {}),
    ]);
    const matchedDeps = [];
    for (const depName of wsAllDeps) {
      if (duplicateWorkspaceNames.has(depName)) {
        warnings.push(
          createScanError(
            ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
            `Dependency "${depName}" declared by "${ws.name}" cannot be resolved because multiple local workspaces share this package name. Relationship is ambiguous and skipped.`,
            {
              workspace: ws.name,
              dependency: depName,
            }
          )
        );
        continue;
      }
      if (workspaceMap.has(depName)) {
        const targetWs = workspaceMap.get(depName);
        const declaredRange = getDeclaredRange(ws, depName);
        if (isVersionCompatible(targetWs.version, declaredRange)) {
          matchedDeps.push(depName);
        } else {
          warnings.push(
            createScanError(
              ErrorCodes.UNRESOLVED_DEPENDENCY,
              `Workspace "${ws.name}" declared dependency "${depName}" with range "${declaredRange}", which is incompatible with local workspace version "${targetWs.version}". Not linked as workspace dependency.`,
              {
                workspace: ws.name,
                dependency: depName,
                declaredRange,
                localVersion: targetWs.version,
              }
            )
          );
        }
      }
    }
    ws.workspaceDependencies = matchedDeps.sort();
  }

  // Build workspaceDependencies adjacency list (keyed by package name, with disambiguation for duplicates)
  const workspaceDependencies = {};
  workspaceDependencies[rootComponent.name] = [...rootComponent.workspaceDependencies];
  for (const ws of workspaces) {
    if (workspaceDependencies[ws.name] === undefined) {
      workspaceDependencies[ws.name] = [...ws.workspaceDependencies];
    } else {
      // Disambiguate duplicate workspace package name in adjacency list
      workspaceDependencies[`${ws.name}#${ws.location.relative}`] = [...ws.workspaceDependencies];
    }
  }

  // Build dependencyEdges adjacency list (keyed by unambiguous bomRef)
  const dependencyEdges = {};
  dependencyEdges[rootComponent.bomRef] = rootComponent.workspaceDependencies
    .map(name => nameToBomRef.get(name))
    .filter(Boolean);
  for (const ws of workspaces) {
    dependencyEdges[ws.bomRef] = ws.workspaceDependencies
      .map(name => nameToBomRef.get(name))
      .filter(Boolean);
  }

  const firstPartyComponents = [rootComponent, ...workspaces];

  // Optional: classify components if passed via options
  let classifiedComponents;
  if (Array.isArray(options.components)) {
    classifiedComponents = classifyComponents(options.components, {
      names: new Set(firstPartyComponents.map(c => c.name)),
      workspaces,
      root: rootComponent,
      firstPartyComponents,
    });
  }

  // Determine overall status
  let status = ScanStatus.COMPLETE;
  if (errors.length > 0) {
    status = ScanStatus.PARTIAL;
  }

  const result = {
    status,
    projectPath: resolvedRootPath,
    root: rootComponent,
    workspaces,
    firstPartyComponents,
    workspaceDependencies,
    dependencyEdges,
    errors,
    warnings,
  };

  if (classifiedComponents !== undefined) {
    result.classifiedComponents = classifiedComponents;
  }

  return result;
}

/**
 * Asynchronously discovers the root application and all local npm workspace packages in a project.
 *
 * @param {string} projectPath - Target project directory path.
 * @param {object} [options={}] - Optional configuration options.
 * @returns {Promise<object>} Result containing discovered first-party components and workspace relationships.
 */
export async function discoverFirstPartyComponents(projectPath, options = {}) {
  return discoverFirstPartyComponentsSync(projectPath, options);
}

/**
 * Alias for discoverFirstPartyComponents.
 */
export const discoverWorkspaces = discoverFirstPartyComponents;

/**
 * Alias for discoverFirstPartyComponentsSync.
 */
export const discoverWorkspacesSync = discoverFirstPartyComponentsSync;

export default discoverFirstPartyComponents;
