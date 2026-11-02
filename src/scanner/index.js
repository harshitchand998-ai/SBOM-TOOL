import { discoverProjectFiles } from '../fileDiscovery.js';
import { parsePackageJson, parsePackageLock } from '../parser.js';
import { resolveDependencies, resolveManifestOnly } from '../dependencyResolver.js';
import { generateCycloneDX } from '../cyclonedxGenerator.js';
import { ScanStatus, ErrorCodes, createScanError } from '../errors.js';

/**
 * The main scanner entry point. Scans a project directory and produces
 * a structured scan result with components, dependency edges, and
 * optionally a CycloneDX SBOM.
 *
 * @param {string} projectPath - Path to the project directory.
 * @returns {Promise<object>} Scan result containing status, components, errors, warnings, and BOM.
 */
export async function scanProject(projectPath) {
  const errors = [];
  const warnings = [];

  // Step 1: Validate and discover project files
  const discovery = discoverProjectFiles(projectPath);
  errors.push(...discovery.errors);
  warnings.push(...discovery.warnings);

  if (discovery.errors.length > 0) {
    return {
      status: ScanStatus.FAILED,
      projectPath: discovery.resolvedPath,
      projectMetadata: null,
      lockfileVersion: null,
      errors,
      warnings,
      components: [],
      dependencyEdges: {},
      bom: null,
    };
  }

  // Step 2: Parse package.json
  if (!discovery.packageJsonPath) {
    return {
      status: ScanStatus.FAILED,
      projectPath: discovery.resolvedPath,
      projectMetadata: null,
      lockfileVersion: null,
      errors,
      warnings,
      components: [],
      dependencyEdges: {},
      bom: null,
    };
  }

  const pkgJsonResult = parsePackageJson(discovery.packageJsonPath);
  errors.push(...pkgJsonResult.errors);
  warnings.push(...pkgJsonResult.warnings);

  if (pkgJsonResult.errors.length > 0 || !pkgJsonResult.data) {
    return {
      status: ScanStatus.FAILED,
      projectPath: discovery.resolvedPath,
      projectMetadata: null,
      lockfileVersion: null,
      errors,
      warnings,
      components: [],
      dependencyEdges: {},
      bom: null,
    };
  }

  // Step 3: Parse package-lock.json (if present)
  let lockfileResult = null;
  let detectedLockfileVersion = null;
  if (discovery.packageLockPath) {
    lockfileResult = parsePackageLock(discovery.packageLockPath);
    detectedLockfileVersion = lockfileResult.lockfileVersion;
    errors.push(...lockfileResult.errors);
    warnings.push(...lockfileResult.warnings);

    if (lockfileResult.errors.length > 0) {
      // Lockfile has errors — fall back to partial scan
      lockfileResult = null;
    }
  }

  // Step 4: Resolve dependencies
  let resolution;
  let status;

  if (lockfileResult && lockfileResult.data) {
    // Full scan with lockfile
    try {
      resolution = resolveDependencies(pkgJsonResult.data, lockfileResult.data);
      warnings.push(...resolution.warnings);
      status = ScanStatus.COMPLETE;
    } catch (err) {
      errors.push(createScanError(
        ErrorCodes.SCAN_ERROR,
        `Dependency resolution failed: ${err.message}`,
        { originalError: err.message }
      ));
      return {
        status: ScanStatus.FAILED,
        projectPath: discovery.resolvedPath,
        projectMetadata: {
          name: pkgJsonResult.data.name,
          version: pkgJsonResult.data.version,
        },
        lockfileVersion: detectedLockfileVersion,
        errors,
        warnings,
        components: [],
        dependencyEdges: {},
        bom: null,
      };
    }
  } else {
    // Partial scan — manifest only
    resolution = resolveManifestOnly(pkgJsonResult.data);
    warnings.push(...resolution.warnings);
    status = ScanStatus.PARTIAL;
  }

  // Step 5: Convert internal representation for output
  const componentsArray = [];
  for (const [, comp] of resolution.components) {
    componentsArray.push({ ...comp });
  }

  const edgesObject = {};
  for (const [ref, deps] of resolution.dependencyEdges) {
    edgesObject[ref] = [...deps];
  }

  // Step 6: Generate CycloneDX BOM (only for complete scans)
  let bom = null;
  if (status === ScanStatus.COMPLETE) {
    try {
      bom = generateCycloneDX({
        rootRef: resolution.rootRef,
        components: resolution.components,
        dependencyEdges: resolution.dependencyEdges,
        projectMetadata: pkgJsonResult.data,
      });
    } catch (err) {
      errors.push(createScanError(
        ErrorCodes.SCAN_ERROR,
        `CycloneDX generation failed: ${err.message}`,
        { originalError: err.message }
      ));
      status = ScanStatus.PARTIAL;
    }
  }

  return {
    status,
    projectPath: discovery.resolvedPath,
    projectMetadata: {
      name: pkgJsonResult.data.name,
      version: pkgJsonResult.data.version,
    },
    lockfileVersion: lockfileResult?.lockfileVersion ?? detectedLockfileVersion ?? null,
    errors,
    warnings,
    components: componentsArray,
    dependencyEdges: edgesObject,
    bom,
  };
}
