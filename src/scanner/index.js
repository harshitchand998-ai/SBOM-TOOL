import fs from 'node:fs';
import path from 'node:path';
import { discoverProjectFiles } from '../fileDiscovery.js';
import { parsePackageJson, parsePackageLock } from '../parser.js';
import { resolveDependencies, resolveManifestOnly } from '../dependencyResolver.js';
import { generateCycloneDX } from '../cyclonedxGenerator.js';
import { discoverFirstPartyComponentsSync } from '../workspaceDiscovery.js';
import { validateStructure } from '../validator.js';
import { checkVulnerabilities } from '../vulnerabilityChecker.js';
import { detectAnomalies, summarizeAnomalies } from '../anomalyDetector.js';
import { compareInventories } from '../dependencyComparison.js';
import { ScanStatus, ErrorCodes, createScanError } from '../errors.js';

/**
 * Synchronously scans a project directory and produces a structured scan result
 * with components, dependency edges, CycloneDX SBOM, and validation information.
 *
 * @param {string} projectPath - Path to the project directory.
 * @returns {object} Scan result containing status, components, errors, warnings, BOM, and validation.
 */
export function scanProjectSync(projectPath) {
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
      validation: null,
      vulnerabilities: null,
      anomalies: null,
      comparison: null,
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
      validation: null,
      vulnerabilities: null,
      anomalies: null,
      comparison: null,
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
      validation: null,
      vulnerabilities: null,
      anomalies: null,
      comparison: null,
    };
  }

  // Step 3: Discover first-party components (root application and local workspaces)
  const fpResult = discoverFirstPartyComponentsSync(discovery.resolvedPath);
  errors.push(...fpResult.errors);
  warnings.push(...fpResult.warnings);

  // Step 4: Parse package-lock.json (if present)
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

  // Step 5: Resolve dependencies
  let resolution;
  let status;

  const resolutionOptions = {
    workspaces: fpResult.workspaces,
    rootComponent: fpResult.root,
    workspaceDependencies: fpResult.workspaceDependencies,
    projectPath: discovery.resolvedPath,
  };

  if (lockfileResult && lockfileResult.data) {
    // Full scan with lockfile
    try {
      resolution = resolveDependencies(pkgJsonResult.data, lockfileResult.data, resolutionOptions);
      warnings.push(...resolution.warnings);
      // Status is COMPLETE unless there are non-fatal workspace/discovery errors
      status = errors.length > 0 ? ScanStatus.PARTIAL : ScanStatus.COMPLETE;
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
        validation: null,
        vulnerabilities: null,
        anomalies: null,
        comparison: null,
      };
    }
  } else {
    // Partial scan — manifest only
    resolution = resolveManifestOnly(pkgJsonResult.data, resolutionOptions);
    warnings.push(...resolution.warnings);
    status = ScanStatus.PARTIAL;
  }

  // Step 6: Convert internal representation for output
  const componentsArray = [];
  for (const [, comp] of resolution.components) {
    componentsArray.push({ ...comp });
  }

  const edgesObject = {};
  for (const [ref, deps] of resolution.dependencyEdges) {
    edgesObject[ref] = [...deps];
  }

  // Step 7: Generate CycloneDX BOM (only for complete scans)
  let bom = null;
  let validation = null;
  if (status === ScanStatus.COMPLETE) {
    try {
      bom = generateCycloneDX({
        rootRef: resolution.rootRef,
        components: resolution.components,
        dependencyEdges: resolution.dependencyEdges,
        projectMetadata: pkgJsonResult.data,
      });

      // Step 8: Validate generated BOM structurally
      validation = validateStructure(bom);
      if (!validation.valid) {
        for (const valErr of validation.errors) {
          errors.push(createScanError(
            ErrorCodes.SCAN_ERROR,
            `BOM validation error: ${valErr}`,
            { validationError: valErr }
          ));
        }
        status = ScanStatus.PARTIAL;
        bom = null; // Do not return an invalid BOM as valid
      }
    } catch (err) {
      errors.push(createScanError(
        ErrorCodes.SCAN_ERROR,
        `CycloneDX generation failed: ${err.message}`,
        { originalError: err.message }
      ));
      status = ScanStatus.PARTIAL;
      bom = null;
      validation = null;
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
    validation,
    vulnerabilities: null,
    anomalies: null,
    comparison: null,
  };
}

/**
 * Asynchronously scans a project directory and produces a structured scan result
 * with components, dependency edges, CycloneDX SBOM, validation information,
 * and optional OSV vulnerability findings, anomaly detection, and dependency comparison.
 *
 * @param {string} projectPath - Path to the project directory.
 * @param {object} [options={}] - Scan options.
 * @param {boolean} [options.vulnerabilities] - Enable OSV vulnerability analysis.
 * @param {boolean} [options.anomalies] - Whether to run anomaly detection (defaults to true for complete scans).
 * @param {object|string} [options.previousBom] - Previous SBOM object or file path for dependency comparison.
 * @param {object|string} [options.previousSbom] - Alias for previousBom.
 * @returns {Promise<object>} Scan result.
 */
export async function scanProject(projectPath, options = {}) {
  const result = scanProjectSync(projectPath);

  // Anomaly detection on complete scans with a valid BOM (enabled by default)
  if (options?.anomalies !== false && result.status === ScanStatus.COMPLETE && result.bom && result.validation?.valid) {
    try {
      const anomalyList = detectAnomalies(result.bom);
      result.anomalies = {
        findings: anomalyList,
        summary: summarizeAnomalies(anomalyList),
      };
    } catch (err) {
      // Anomaly detection failure must not invalidate the SBOM
      result.warnings.push(createScanError(
        ErrorCodes.SCAN_ERROR,
        `Anomaly detection encountered an error: ${err.message}`,
        { originalError: err.message }
      ));
      result.anomalies = null;
    }
  }

  // Vulnerability analysis
  if (options && options.vulnerabilities) {
    if (result.status === ScanStatus.COMPLETE && result.bom && result.validation?.valid) {
      result.vulnerabilities = await checkVulnerabilities(result, options);
    } else {
      result.vulnerabilities = null;
    }
  }

  // Dependency comparison when a previous SBOM is provided (previousBom or previousSbom)
  const prevOption = options?.previousBom || options?.previousSbom;
  if (prevOption) {
    // Comparison results are not generated using incomplete or invalid current SBOM data
    if (result.status === ScanStatus.COMPLETE && result.bom && result.validation?.valid) {
      let prevBomData = null;
      if (typeof prevOption === 'string') {
        const trimmed = prevOption.trim();
        if (trimmed.startsWith('{')) {
          try {
            prevBomData = JSON.parse(trimmed);
          } catch (err) {
            result.warnings.push(createScanError(
              ErrorCodes.INVALID_PACKAGE_FILE,
              `Malformed previous SBOM JSON string: ${err.message}`,
              { originalError: err.message }
            ));
          }
        } else {
          try {
            const resolvedPrevPath = path.resolve(prevOption);
            if (!fs.existsSync(resolvedPrevPath)) {
              result.warnings.push(createScanError(
                ErrorCodes.PACKAGE_FILE_NOT_FOUND,
                `Previous SBOM file not found: ${prevOption}`,
                { file: prevOption }
              ));
            } else {
              const fileContent = fs.readFileSync(resolvedPrevPath, 'utf8');
              prevBomData = JSON.parse(fileContent);
            }
          } catch (err) {
            result.warnings.push(createScanError(
              ErrorCodes.INVALID_PACKAGE_FILE,
              `Failed to read previous SBOM file: ${err.message}`,
              { file: prevOption, originalError: err.message }
            ));
          }
        }
      } else if (typeof prevOption === 'object' && prevOption !== null) {
        prevBomData = prevOption;
      }

      if (prevBomData) {
        try {
          const compResult = compareInventories(prevBomData, result.bom);
          result.comparison = compResult;
          if (compResult.status === 'failed' && compResult.errors?.length > 0) {
            for (const cErr of compResult.errors) {
              result.warnings.push(createScanError(
                ErrorCodes.SCAN_ERROR,
                `Dependency comparison warning: ${cErr.message || cErr}`,
                { comparisonError: cErr }
              ));
            }
          }
        } catch (err) {
          result.warnings.push(createScanError(
            ErrorCodes.SCAN_ERROR,
            `Dependency comparison failed: ${err.message}`,
            { originalError: err.message }
          ));
          result.comparison = null;
        }
      } else {
        result.comparison = null;
      }
    } else {
      // Comparison skipped: complete and valid current SBOM required
      result.warnings.push(createScanError(
        ErrorCodes.SCAN_ERROR,
        'Dependency comparison skipped: complete and valid current CycloneDX SBOM is required',
        { scanStatus: result.status }
      ));
      result.comparison = null;
    }
  }

  return result;
}

export default scanProject;
