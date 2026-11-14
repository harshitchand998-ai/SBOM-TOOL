import fs from 'node:fs';
import path from 'node:path';
import { ScanStatus, ErrorCodes, createScanError } from './errors.js';

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
    const rawScore = f.severity?.score;
    const scoreVal = parseFloat(rawScore);
    const scoreStr = String(rawScore ?? '').toUpperCase();

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
 * Generates a structured combined scan report summarizing metadata, project info,
 * component statistics, SBOM, validation, vulnerabilities, anomalies, and comparison.
 *
 * @param {object} scanResult - Complete scan result from scanProject.
 * @param {object} [options={}] - Report construction options.
 * @returns {object} Combined report structure.
 */
export function generateReport(scanResult, options = {}) {
  const components = Array.isArray(scanResult?.components) ? scanResult.components : [];
  const nonRoot = components.filter(c => !c.isRoot);
  const directDeps = nonRoot.filter(c => c.dependencyType === 'direct').length;
  const transitiveDeps = nonRoot.filter(c => c.dependencyType === 'transitive').length;
  const workspacePackages = nonRoot.filter(c => c.isFirstParty || c.dependencyType === 'workspace').length;

  let toolVersion = '0.1.0';
  try {
    const pkgJsonPath = new URL('../package.json', import.meta.url);
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
      status: scanResult?.status || 'failed',
    },
    components: {
      total: nonRoot.length,
      direct: directDeps,
      transitive: transitiveDeps,
      workspace: workspacePackages,
    },
    sbom: null,
    validation: scanResult?.validation || null,
    vulnerabilities: null,
    anomalies: null,
    comparison: null,
    errors: Array.isArray(scanResult?.errors) ? [...scanResult.errors] : [],
    warnings: Array.isArray(scanResult?.warnings) ? [...scanResult.warnings] : [],
    status: scanResult?.status || 'failed',
  };

  if (scanResult?.bom && scanResult?.validation?.valid !== false) {
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
      scannedPackages: v.scannedPackages ?? 0,
      totalPackages: v.totalPackages ?? 0,
      vulnerablePackages: v.vulnerablePackages ?? 0,
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
      status: a.status || 'completed',
      total: a.summary?.total || 0,
      summary: a.summary || {
        total: a.findings?.length || 0,
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
 * Alias for backward compatibility with Order 18.
 */
export const buildCombinedReport = generateReport;

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
export function generateReportFiles(outputDir, scanResult, options = {}) {
  const resolvedDir = path.resolve(outputDir);
  if (!fs.existsSync(resolvedDir)) {
    fs.mkdirSync(resolvedDir, { recursive: true });
  }

  const writtenFiles = {};
  const report = generateReport(scanResult, options);

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
 * Alias for backward compatibility with Order 18.
 */
export const writeMultiFileOutput = generateReportFiles;

