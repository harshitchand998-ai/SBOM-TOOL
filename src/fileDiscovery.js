import fs from 'node:fs';
import path from 'node:path';
import { ErrorCodes, createScanError } from './errors.js';

/**
 * Names of unsupported package-manager lockfiles.
 * If any of these exist alongside (or instead of) package-lock.json we report the limitation.
 */
const UNSUPPORTED_LOCKFILES = Object.freeze({
  'yarn.lock': 'Yarn',
  'pnpm-lock.yaml': 'pnpm',
  'bun.lock': 'Bun',
  'bun.lockb': 'Bun',
});

/**
 * Validates a project directory and discovers the required input files.
 *
 * @param {string} projectPath - Absolute or relative path to the target project directory.
 * @returns {{
 *   resolvedPath: string,
 *   packageJsonPath: string | null,
 *   packageLockPath: string | null,
 *   errors: Array<object>,
 *   warnings: Array<object>
 * }}
 */
export function discoverProjectFiles(projectPath) {
  const errors = [];
  const warnings = [];

  // Check valid path argument
  if (typeof projectPath !== 'string' || projectPath.trim() === '') {
    errors.push(createScanError(
      ErrorCodes.PROJECT_NOT_FOUND,
      `Project path must be a non-empty string, received: ${JSON.stringify(projectPath)}`,
      { path: projectPath }
    ));
    return {
      resolvedPath: typeof projectPath === 'string' ? projectPath : '',
      packageJsonPath: null,
      packageLockPath: null,
      errors,
      warnings,
    };
  }

  const resolvedPath = path.resolve(projectPath);

  // 1. Check existence
  if (!fs.existsSync(resolvedPath)) {
    errors.push(createScanError(
      ErrorCodes.PROJECT_NOT_FOUND,
      `Project directory does not exist: ${resolvedPath}`,
      { path: resolvedPath }
    ));
    return { resolvedPath, packageJsonPath: null, packageLockPath: null, errors, warnings };
  }

  // 2. Check that it is a directory
  let stats;
  try {
    stats = fs.statSync(resolvedPath);
  } catch (err) {
    errors.push(createScanError(
      ErrorCodes.PROJECT_ACCESS_DENIED,
      `Cannot access project directory: ${resolvedPath}`,
      { path: resolvedPath, originalError: err.message }
    ));
    return { resolvedPath, packageJsonPath: null, packageLockPath: null, errors, warnings };
  }

  if (!stats.isDirectory()) {
    errors.push(createScanError(
      ErrorCodes.PROJECT_NOT_FOUND,
      `Supplied path is not a directory: ${resolvedPath}`,
      { path: resolvedPath }
    ));
    return { resolvedPath, packageJsonPath: null, packageLockPath: null, errors, warnings };
  }

  // 3. Detect unsupported package managers
  for (const [lockfileName, managerName] of Object.entries(UNSUPPORTED_LOCKFILES)) {
    const lockfilePath = path.join(resolvedPath, lockfileName);
    if (fs.existsSync(lockfilePath)) {
      errors.push(createScanError(
        ErrorCodes.UNSUPPORTED_PACKAGE_MANAGER,
        `Unsupported package manager detected: ${managerName} (found ${lockfileName}). Only npm is supported.`,
        { file: lockfileName, packageManager: managerName }
      ));
    }
  }

  // If unsupported lockfiles were found, return early
  if (errors.length > 0) {
    return { resolvedPath, packageJsonPath: null, packageLockPath: null, errors, warnings };
  }

  // 4. Locate package.json
  const packageJsonPath = path.join(resolvedPath, 'package.json');
  let hasPackageJson = false;
  try {
    fs.accessSync(packageJsonPath, fs.constants.R_OK);
    hasPackageJson = true;
  } catch {
    // not accessible
  }

  if (!hasPackageJson) {
    errors.push(createScanError(
      ErrorCodes.PACKAGE_FILE_NOT_FOUND,
      'package.json not found in the project directory.',
      { file: 'package.json', path: resolvedPath }
    ));
  }

  // 5. Locate package-lock.json
  const packageLockPath = path.join(resolvedPath, 'package-lock.json');
  let hasPackageLock = false;
  try {
    fs.accessSync(packageLockPath, fs.constants.R_OK);
    hasPackageLock = true;
  } catch {
    // not accessible
  }

  if (hasPackageJson && !hasPackageLock) {
    warnings.push(createScanError(
      ErrorCodes.PACKAGE_FILE_NOT_FOUND,
      'package-lock.json not found. Only a partial scan (manifest-only) is possible. Transitive dependencies and exact resolved versions cannot be guaranteed.',
      { file: 'package-lock.json', path: resolvedPath }
    ));
  }

  return {
    resolvedPath,
    packageJsonPath: hasPackageJson ? packageJsonPath : null,
    packageLockPath: hasPackageLock ? packageLockPath : null,
    errors,
    warnings,
  };
}
