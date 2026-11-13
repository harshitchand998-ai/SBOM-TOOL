import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from '../scanner/index.js';
import { ScanStatus, ErrorCodes, createScanError } from '../errors.js';

/**
 * Initializes and runs the SBOM engine against a specified target project path.
 * Retained for backward compatibility.
 *
 * @param {string} targetPath - Relative or absolute path to the target project to analyze.
 * @param {object} [options={}] - Optional configuration options for the analysis.
 * @returns {Promise<object>} Structured data object representing engine status and target metadata.
 */
export async function runEngine(targetPath, options = {}) {
  if (typeof targetPath !== 'string' || targetPath.trim() === '') {
    throw new TypeError('Target project path must be a non-empty string');
  }

  const resolvedPath = path.resolve(targetPath);

  return {
    targetPath: resolvedPath,
    status: 'initialized',
    timestamp: new Date().toISOString(),
    engine: {
      name: 'npm-sbom-tool',
      version: '0.1.0'
    },
    options,
    data: null
  };
}

/**
 * Alias for runEngine to provide intuitive domain-specific naming.
 */
export const generateSbom = runEngine;

/**
 * Computes vulnerability severity counts from findings.
 *
 * @param {Array<object>} findings - Vulnerability findings.
 * @returns {{ critical: number, high: number, medium: number, low: number, unknown: number }}
 */
export function computeSeverityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  if (!Array.isArray(findings)) return counts;

  for (const f of findings) {
    const scoreVal = parseFloat(f.severity?.score);
    const scoreStr = (f.severity?.score || '').toUpperCase();

    if (scoreStr.includes('CRITICAL') || scoreVal >= 9.0) {
      counts.critical++;
    } else if (scoreStr.includes('HIGH') || scoreVal >= 7.0) {
      counts.high++;
    } else if (scoreStr.includes('MODERATE') || scoreStr.includes('MEDIUM') || scoreVal >= 4.0) {
      counts.medium++;
    } else if (scoreStr.includes('LOW') || (scoreVal > 0.0 && scoreVal < 4.0)) {
      counts.low++;
    } else {
      counts.unknown++;
    }
  }
  return counts;
}

/**
 * Constructs a combined scan report summarizing metadata, project info, SBOM,
 * validation, vulnerabilities, anomalies, comparison, and scan status.
 *
 * @param {object} scanResult - Complete scan result from scanProject.
 * @param {object} [options={}] - Report construction options.
 * @returns {object} Combined report structure.
 */
export function buildCombinedReport(scanResult, options = {}) {
  const components = Array.isArray(scanResult?.components) ? scanResult.components : [];
  const nonRoot = components.filter(c => !c.isRoot);
  const directDeps = nonRoot.filter(c => c.dependencyType === 'direct').length;
  const transitiveDeps = nonRoot.filter(c => c.dependencyType === 'transitive').length;
  const workspacePackages = nonRoot.filter(c => c.isFirstParty || c.dependencyType === 'workspace').length;

  let toolVersion = '0.1.0';
  try {
    const pkgJsonPath = new URL('../../package.json', import.meta.url);
    const pkgData = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    toolVersion = pkgData.version || '0.1.0';
  } catch {}

  const report = {
    scan: {
      tool: 'npm-sbom-tool',
      version: toolVersion,
      timestamp: new Date().toISOString(),
      projectPath: scanResult?.projectPath || null,
      status: scanResult?.status || 'failed',
    },
    project: {
      name: scanResult?.projectMetadata?.name || (scanResult?.projectPath ? path.basename(scanResult.projectPath) : 'unknown'),
      version: scanResult?.projectMetadata?.version || '0.0.0',
      path: scanResult?.projectPath || null,
    },
    sbom: null,
    validation: scanResult?.validation || null,
    vulnerabilities: null,
    anomalies: null,
    comparison: null,
    errors: scanResult?.errors || [],
    warnings: scanResult?.warnings || [],
    status: scanResult?.status || 'failed',
  };

  if (scanResult?.bom) {
    report.sbom = {
      format: scanResult.bom.bomFormat || 'CycloneDX',
      specVersion: scanResult.bom.specVersion || '1.7',
      serialNumber: scanResult.bom.serialNumber || null,
      version: scanResult.bom.version || 1,
      componentsCount: Array.isArray(scanResult.bom.components) ? scanResult.bom.components.length : 0,
      dependenciesCount: Array.isArray(scanResult.bom.dependencies) ? scanResult.bom.dependencies.length : 0,
      summary: {
        totalComponents: nonRoot.length,
        directDependencies: directDeps,
        transitiveDependencies: transitiveDeps,
        workspacePackages,
      },
    };
  }

  if (scanResult?.vulnerabilities) {
    const v = scanResult.vulnerabilities;
    const sev = computeSeverityCounts(v.findings);
    report.vulnerabilities = {
      status: v.status,
      scannedPackages: v.scannedPackages,
      totalPackages: v.totalPackages,
      vulnerablePackages: v.vulnerablePackages,
      summary: {
        total: v.findings?.length || 0,
        critical: sev.critical,
        high: sev.high,
        medium: sev.medium,
        low: sev.low,
        unknown: sev.unknown,
      },
      findings: v.findings || [],
      warnings: v.warnings || [],
      errors: v.errors || [],
    };
  }

  if (scanResult?.anomalies) {
    const a = scanResult.anomalies;
    report.anomalies = {
      status: 'completed',
      total: a.summary?.total || 0,
      summary: a.summary || {
        total: 0,
        bySeverity: { error: 0, warning: 0, info: 0 },
        byType: {},
      },
      findings: a.findings || [],
    };
  }

  if (scanResult?.comparison) {
    report.comparison = scanResult.comparison;
  }

  return report;
}

/**
 * Writes the multi-file full scan report structure into a destination directory:
 *   output/
 *   ├── sbom.json
 *   ├── vulnerabilities.json
 *   ├── anomalies.json
 *   └── report.json
 *
 * @param {string} outputDir - Directory to write the report files into.
 * @param {object} scanResult - Scan result object.
 * @param {object} [options={}] - Options.
 * @returns {object} Paths of written files.
 */
export function writeMultiFileOutput(outputDir, scanResult, options = {}) {
  const resolvedDir = path.resolve(outputDir);
  if (!fs.existsSync(resolvedDir)) {
    fs.mkdirSync(resolvedDir, { recursive: true });
  }

  const writtenFiles = {};
  const report = buildCombinedReport(scanResult, options);

  // 1. sbom.json: CycloneDX SBOM (written only when a valid BOM exists)
  const sbomPath = path.join(resolvedDir, 'sbom.json');
  if (scanResult.bom && scanResult.validation?.valid) {
    fs.writeFileSync(sbomPath, JSON.stringify(scanResult.bom, null, 2) + '\n', 'utf8');
    writtenFiles.sbom = sbomPath;
  } else if (fs.existsSync(sbomPath)) {
    try {
      fs.rmSync(sbomPath, { force: true });
    } catch (err) {
      const cleanupWarning = createScanError(
        ErrorCodes.SCAN_ERROR,
        `Failed to remove stale sbom.json from previous scan: ${err.message}`,
        { file: sbomPath, originalError: err.message }
      );
      if (Array.isArray(scanResult.warnings)) {
        scanResult.warnings.push(cleanupWarning);
      }
      if (Array.isArray(report.warnings)) {
        report.warnings.push(cleanupWarning);
      }
      writtenFiles.cleanupWarning = cleanupWarning;
    }
  }

  // 2. vulnerabilities.json: structured vulnerability findings or skipped notice
  const vulnPath = path.join(resolvedDir, 'vulnerabilities.json');
  if (report.vulnerabilities) {
    fs.writeFileSync(vulnPath, JSON.stringify(report.vulnerabilities, null, 2) + '\n', 'utf8');
  } else {
    fs.writeFileSync(vulnPath, JSON.stringify({
      status: 'skipped',
      reason: scanResult.status !== ScanStatus.COMPLETE
        ? 'Vulnerability analysis skipped: complete and valid CycloneDX SBOM required.'
        : 'Vulnerability analysis was not requested.',
    }, null, 2) + '\n', 'utf8');
  }
  writtenFiles.vulnerabilities = vulnPath;

  // 3. anomalies.json: structured anomaly findings or skipped notice
  const anomalyPath = path.join(resolvedDir, 'anomalies.json');
  if (report.anomalies) {
    fs.writeFileSync(anomalyPath, JSON.stringify(report.anomalies, null, 2) + '\n', 'utf8');
  } else {
    fs.writeFileSync(anomalyPath, JSON.stringify({
      status: 'skipped',
      reason: scanResult.status !== ScanStatus.COMPLETE
        ? 'Anomaly detection skipped: complete and valid CycloneDX SBOM required.'
        : 'Anomaly detection was not requested.',
    }, null, 2) + '\n', 'utf8');
  }
  writtenFiles.anomalies = anomalyPath;

  // 4. report.json: combined scan report
  const reportPath = path.join(resolvedDir, 'report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  writtenFiles.report = reportPath;

  return writtenFiles;
}

/**
 * Connects the 'scan' command workflow to the engine.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options (e.g. full, vulnerabilities, previousSbom).
 * @returns {Promise<object>} Scan result.
 */
export async function executeScan(projectPath, options = {}) {
  const scanOpts = { ...options };

  if (options.full) {
    scanOpts.vulnerabilities = true;
    scanOpts.anomalies = true;
  }

  if (options.previousSbom && !scanOpts.previousBom) {
    scanOpts.previousBom = options.previousSbom;
  }

  return await scanProject(projectPath, scanOpts);
}

/**
 * Connects the 'sbom' command workflow to the engine.
 * Generates a CycloneDX SBOM document without running vulnerability or anomaly analysis.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options.
 * @returns {Promise<object>} Result containing success boolean, bom, and diagnostic info.
 */
export async function executeSbom(projectPath, options = {}) {
  // sbom command generates CycloneDX SBOM; no vulnerability or anomaly analysis
  const scanOpts = {
    ...options,
    vulnerabilities: false,
    anomalies: false,
  };

  const result = await scanProject(projectPath, scanOpts);

  if (result.status === ScanStatus.FAILED) {
    return {
      success: false,
      status: result.status,
      bom: null,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Scan failed. Unable to generate CycloneDX SBOM.',
    };
  }

  if (result.status === ScanStatus.PARTIAL || !result.bom) {
    return {
      success: false,
      status: result.status,
      bom: null,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Cannot generate CycloneDX SBOM for partial scan (package-lock.json is required).',
    };
  }

  if (result.validation && !result.validation.valid) {
    return {
      success: false,
      status: result.status,
      bom: result.bom,
      validation: result.validation,
      errors: result.errors,
      warnings: result.warnings,
      projectMetadata: result.projectMetadata,
      message: 'Generated CycloneDX SBOM failed validation.',
    };
  }

  return {
    success: true,
    status: result.status,
    bom: result.bom,
    validation: result.validation,
    errors: result.errors,
    warnings: result.warnings,
    projectMetadata: result.projectMetadata,
  };
}

/**
 * Connects the 'audit' command workflow to the engine.
 * Performs vulnerability and anomaly analysis, distinguishing findings.
 *
 * @param {string} projectPath - Path to project directory.
 * @param {object} [options={}] - Options (e.g. vuln, anomaly, previousSbom).
 * @returns {Promise<object>} Audit report object.
 */
export async function executeAudit(projectPath, options = {}) {
  const runVuln = Boolean(options.vuln) || (!options.vuln && !options.anomaly);
  const runAnomaly = Boolean(options.anomaly) || (!options.vuln && !options.anomaly);

  const scanOpts = {
    ...options,
    vulnerabilities: runVuln,
    anomalies: runAnomaly,
  };

  if (options.previousSbom && !scanOpts.previousBom) {
    scanOpts.previousBom = options.previousSbom;
  }

  const scanResult = await scanProject(projectPath, scanOpts);
  const resolvedProject = scanResult.projectPath || path.resolve(projectPath);

  if (scanResult.status === ScanStatus.FAILED) {
    return {
      success: false,
      project: {
        name: scanResult.projectMetadata?.name || path.basename(resolvedProject),
        version: scanResult.projectMetadata?.version || '0.0.0',
        path: resolvedProject,
      },
      summary: { dependenciesScanned: 0 },
      status: 'failed',
      errors: scanResult.errors,
      warnings: scanResult.warnings,
      vulnerabilities: null,
      anomalies: null,
      comparison: null,
    };
  }

  const components = Array.isArray(scanResult.components) ? scanResult.components : [];
  const scannedDepsCount = components.filter(c => !c.isRoot).length;

  let overallStatus = 'completed';
  if (scanResult.status === ScanStatus.PARTIAL) {
    overallStatus = 'partial';
  } else if (scanResult.vulnerabilities && (scanResult.vulnerabilities.status === 'failed' || scanResult.vulnerabilities.status === 'partial')) {
    overallStatus = scanResult.vulnerabilities.status;
  }

  const report = {
    success: true,
    project: {
      name: scanResult.projectMetadata?.name || path.basename(resolvedProject),
      version: scanResult.projectMetadata?.version || '0.0.0',
      path: resolvedProject,
    },
    summary: {
      dependenciesScanned: scannedDepsCount,
    },
    status: overallStatus,
    scanStatus: scanResult.status,
  };

  if (runVuln) {
    if (scanResult.vulnerabilities) {
      report.summary.vulnerabilitiesFound = scanResult.vulnerabilities.findings?.length || 0;
      report.vulnerabilities = {
        status: scanResult.vulnerabilities.status,
        scannedPackages: scanResult.vulnerabilities.scannedPackages,
        totalPackages: scanResult.vulnerabilities.totalPackages,
        vulnerablePackages: scanResult.vulnerabilities.vulnerablePackages,
        findings: scanResult.vulnerabilities.findings || [],
        warnings: scanResult.vulnerabilities.warnings || [],
        errors: scanResult.vulnerabilities.errors || [],
      };
    } else {
      report.vulnerabilities = null;
    }
  }

  if (runAnomaly) {
    if (scanResult.anomalies) {
      report.summary.anomaliesFound = scanResult.anomalies.summary?.total || 0;
      report.anomalies = {
        total: scanResult.anomalies.summary?.total || 0,
        bySeverity: scanResult.anomalies.summary?.bySeverity || { error: 0, warning: 0, info: 0 },
        byType: scanResult.anomalies.summary?.byType || {},
        findings: scanResult.anomalies.findings || [],
      };
    } else {
      report.anomalies = null;
    }
  }

  if (scanResult.comparison) {
    report.summary.comparison = scanResult.comparison.summary;
    report.comparison = scanResult.comparison;
  }

  return report;
}

export default runEngine;
