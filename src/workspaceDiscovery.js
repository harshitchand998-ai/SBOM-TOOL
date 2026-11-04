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
 * Recursively resolves pattern segments against the filesystem to find matching directories.
 * Strictly excludes node_modules and hidden directories.
 *
 * @param {string} currentDir - Currently inspected directory.
 * @param {number} segmentIndex - Index in the parts array.
 * @param {string[]} parts - Split pattern segments.
 * @param {string} projectRoot - Root project directory.
 * @param {string[]} matchedDirs - Output array for matched directory paths.
 */
function matchSegments(currentDir, segmentIndex, parts, projectRoot, matchedDirs) {
  if (segmentIndex >= parts.length) {
    if (currentDir !== projectRoot) {
      try {
        const stat = fs.statSync(currentDir);
        if (stat.isDirectory()) {
          matchedDirs.push(currentDir);
        }
      } catch {
        // Inaccessible directory
      }
    }
    return;
  }

  const segment = parts[segmentIndex];

  if (segment === '**') {
    matchSegments(currentDir, segmentIndex + 1, parts, projectRoot, matchedDirs);
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name !== 'node_modules' && !entry.name.startsWith('.')) {
          const subDir = path.join(currentDir, entry.name);
          matchSegments(subDir, segmentIndex, parts, projectRoot, matchedDirs);
        }
      }
    } catch {
      // Inaccessible directory
    }
  } else if (segment.includes('*') || segment.includes('?')) {
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
        if (
          entry.isDirectory() &&
          entry.name !== 'node_modules' &&
          !entry.name.startsWith('.') &&
          regex.test(entry.name)
        ) {
          const subDir = path.join(currentDir, entry.name);
          matchSegments(subDir, segmentIndex + 1, parts, projectRoot, matchedDirs);
        }
      }
    } catch {
      // Inaccessible directory
    }
  } else {
    if (segment === 'node_modules') return;

    const subDir = path.join(currentDir, segment);
    try {
      if (fs.existsSync(subDir)) {
        const stat = fs.statSync(subDir);
        if (stat.isDirectory()) {
          matchSegments(subDir, segmentIndex + 1, parts, projectRoot, matchedDirs);
        }
      }
    } catch {
      // Inaccessible directory
    }
  }
}

/**
 * Resolves workspace glob patterns into unique directory paths.
 *
 * @param {string} projectRoot - Absolute path to the project root.
 * @param {string[]} patterns - Array of workspace glob patterns.
 * @returns {{
 *   directories: string[],
 *   emptyPatterns: string[],
 *   missingLiteralPaths: string[]
 * }}
 */
function resolveWorkspaceDirectories(projectRoot, patterns) {
  const allMatched = [];
  const emptyPatterns = [];
  const missingLiteralPaths = [];

  for (const rawPattern of patterns) {
    let clean = rawPattern.trim();
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
    matchSegments(projectRoot, 0, parts, projectRoot, patternMatches);

    if (patternMatches.length === 0) {
      emptyPatterns.push(rawPattern);
    } else {
      allMatched.push(...patternMatches);
    }
  }

  const seenPaths = new Set();
  const directories = [];

  for (const dir of allMatched) {
    const resolved = path.resolve(dir);
    if (!seenPaths.has(resolved)) {
      seenPaths.add(resolved);
      directories.push(resolved);
    }
  }

  return { directories, emptyPatterns, missingLiteralPaths };
}

/**
 * Synchronously discovers the root application and all local npm workspace packages in a project.
 *
 * @param {string} projectPath - Target project directory path.
 * @param {object} [options={}] - Optional configuration options.
 * @returns {{
 *   status: string,
 *   projectPath: string,
 *   root: object | null,
 *   workspaces: object[],
 *   firstPartyComponents: object[],
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
      errors,
      warnings,
    };
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
  };

  // 3. Workspace resolution
  const workspaces = [];

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
        errors,
        warnings,
      };
    }

    if (patterns.length > 0) {
      const { directories, emptyPatterns, missingLiteralPaths } = resolveWorkspaceDirectories(
        resolvedRootPath,
        patterns
      );

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
            ErrorCodes.UNRESOLVED_DEPENDENCY,
            `Workspace pattern "${emptyPattern}" matched no packages.`,
            { pattern: emptyPattern }
          )
        );
      }

      // Read each discovered workspace directory
      for (const wsDir of directories) {
        const wsPkgPath = path.join(wsDir, 'package.json');
        const relativeLoc = normalizePath(path.relative(resolvedRootPath, wsDir));

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
        const wsPurl = `pkg:npm/${encodePackageName(wsData.name)}@${wsData.version}`;

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
          purl: wsPurl,
          bomRef: wsPurl,
          dependencies: { ...wsData.dependencies },
          devDependencies: { ...wsData.devDependencies },
          optionalDependencies: { ...wsData.optionalDependencies },
          peerDependencies: { ...wsData.peerDependencies },
        });
      }
    }
  }

  const firstPartyComponents = [rootComponent, ...workspaces];

  let status = ScanStatus.COMPLETE;
  if (errors.length > 0) {
    status = ScanStatus.PARTIAL;
  }

  return {
    status,
    projectPath: resolvedRootPath,
    root: rootComponent,
    workspaces,
    firstPartyComponents,
    errors,
    warnings,
  };
}

/**
 * Asynchronously discovers the root application and all local npm workspace packages in a project.
 *
 * @param {string} projectPath - Target project directory path.
 * @param {object} [options={}] - Optional configuration options.
 * @returns {Promise<object>} Result containing discovered first-party components.
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
