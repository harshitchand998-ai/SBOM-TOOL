import fs from 'node:fs';
import { ErrorCodes, createScanError } from './errors.js';

/**
 * Supported npm lockfile versions.
 */
const SUPPORTED_LOCKFILE_VERSIONS = new Set([2, 3]);

/**
 * Parses a package.json file and extracts project metadata and dependency declarations.
 *
 * @param {string} filePath - Absolute path to the package.json file.
 * @returns {{
 *   data: object | null,
 *   errors: Array<object>,
 *   warnings: Array<object>
 * }}
 */
export function parsePackageJson(filePath) {
  const errors = [];
  const warnings = [];

  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      `Unable to read package.json: ${err.message}`,
      { file: 'package.json', path: filePath }
    ));
    return { data: null, errors, warnings };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      `Unable to parse package.json: ${err.message}`,
      { file: 'package.json', path: filePath }
    ));
    return { data: null, errors, warnings };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package.json must be a JSON object.',
      { file: 'package.json', path: filePath }
    ));
    return { data: null, errors, warnings };
  }

  // Detect workspace configurations (unsupported in V1)
  if (parsed.workspaces) {
    errors.push(createScanError(
      ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT,
      'npm workspaces are not supported in this version of the scanner.',
      { file: 'package.json' }
    ));
    return { data: null, errors, warnings };
  }

  const name = parsed.name || 'unnamed-project';
  const version = parsed.version || '0.0.0';

  if (!parsed.name) {
    warnings.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package.json is missing the "name" field. Using "unnamed-project".',
      { file: 'package.json' }
    ));
  }

  if (!parsed.version) {
    warnings.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package.json is missing the "version" field. Using "0.0.0".',
      { file: 'package.json' }
    ));
  }

  const normalizeDependencyMap = (rawMap) => {
    if (typeof rawMap === 'object' && rawMap !== null && !Array.isArray(rawMap)) {
      return rawMap;
    }
    return {};
  };

  const data = {
    name,
    version,
    description: parsed.description || '',
    license: parsed.license || '',
    dependencies: normalizeDependencyMap(parsed.dependencies),
    devDependencies: normalizeDependencyMap(parsed.devDependencies),
    optionalDependencies: normalizeDependencyMap(parsed.optionalDependencies),
    peerDependencies: normalizeDependencyMap(parsed.peerDependencies),
  };

  return { data, errors, warnings };
}

/**
 * Parses a package-lock.json file and extracts resolved package information.
 *
 * @param {string} filePath - Absolute path to the package-lock.json file.
 * @returns {{
 *   data: object | null,
 *   lockfileVersion: number | null,
 *   errors: Array<object>,
 *   warnings: Array<object>
 * }}
 */
export function parsePackageLock(filePath) {
  const errors = [];
  const warnings = [];

  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      `Unable to read package-lock.json: ${err.message}`,
      { file: 'package-lock.json', path: filePath }
    ));
    return { data: null, lockfileVersion: null, errors, warnings };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      `Unable to parse package-lock.json: ${err.message}`,
      { file: 'package-lock.json', path: filePath }
    ));
    return { data: null, lockfileVersion: null, errors, warnings };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package-lock.json must be a JSON object.',
      { file: 'package-lock.json', path: filePath }
    ));
    return { data: null, lockfileVersion: null, errors, warnings };
  }

  const lockfileVersion = parsed.lockfileVersion;

  if (lockfileVersion === undefined || lockfileVersion === null) {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package-lock.json is missing the "lockfileVersion" field.',
      { file: 'package-lock.json' }
    ));
    return { data: null, lockfileVersion: null, errors, warnings };
  }

  if (!SUPPORTED_LOCKFILE_VERSIONS.has(lockfileVersion)) {
    errors.push(createScanError(
      ErrorCodes.UNSUPPORTED_LOCKFILE_VERSION,
      `Unsupported npm lockfile version: ${lockfileVersion}. Supported versions: ${[...SUPPORTED_LOCKFILE_VERSIONS].join(', ')}.`,
      { file: 'package-lock.json', lockfileVersion }
    ));
    return { data: null, lockfileVersion, errors, warnings };
  }

  if (!parsed.packages || typeof parsed.packages !== 'object') {
    errors.push(createScanError(
      ErrorCodes.INVALID_PACKAGE_FILE,
      'package-lock.json is missing the "packages" section.',
      { file: 'package-lock.json' }
    ));
    return { data: null, lockfileVersion, errors, warnings };
  }

  return { data: parsed, lockfileVersion, errors, warnings };
}
