import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  generateReport,
  generateReportFiles,
  buildCombinedReport,
  writeMultiFileOutput,
  computeSeverityCounts,
} from '../src/reportGenerator.js';
import { executeScan } from '../src/engine/index.js';
import { validateStructure } from '../src/validator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, '..', 'fixtures');
const simplePath = path.join(fixturesDir, 'simple-project');
const missingLockfilePath = path.join(fixturesDir, 'missing-lockfile-project');
const zeroDepsPath = path.join(fixturesDir, 'zero-deps-project');

describe('Order 19: Report Generation (src/reportGenerator.js)', () => {

  // ========================================================
  // 1. Severity Counts Unit Tests
  // ========================================================
  describe('computeSeverityCounts', () => {
    it('accurately groups vulnerabilities into critical, high, medium, low, unknown', () => {
      const findings = [
        { id: 'VULN-1', severity: { score: '9.8' } },
        { id: 'VULN-2', severity: { score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 'CRITICAL' } },
        { id: 'VULN-3', severity: { score: '7.5' } },
        { id: 'VULN-4', severity: { score: 'HIGH' } },
        { id: 'VULN-5', severity: { score: '5.3' } },
        { id: 'VULN-6', severity: { score: 'MEDIUM' } },
        { id: 'VULN-7', severity: { score: '3.1' } },
        { id: 'VULN-8', severity: { score: 'LOW' } },
        { id: 'VULN-9', severity: null },
        { id: 'VULN-10', severity: { score: 'UNKNOWN' } },
      ];

      const counts = computeSeverityCounts(findings);
      assert.equal(counts.critical, 2);
      assert.equal(counts.high, 2);
      assert.equal(counts.medium, 2);
      assert.equal(counts.low, 2);
      assert.equal(counts.unknown, 2);
    });

    it('returns all zeros for empty or non-array findings', () => {
      assert.deepEqual(computeSeverityCounts([]), { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
      assert.deepEqual(computeSeverityCounts(null), { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
    });
  });

  // ========================================================
  // 2. Report Generation Structure
  // ========================================================
  describe('generateReport Structure & Completeness', () => {
    it('generates structured report with all required sections for complete scan', async () => {
      const scanResult = await executeScan(simplePath, {
        full: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({
          package: p,
          vulnerabilities: p.name === 'is-odd' ? [{
            id: 'GHSA-1',
            severity: [{ type: 'CVSS_V3', score: '8.0' }],
            affected: [
              {
                package: { name: 'is-odd', ecosystem: 'npm' },
                ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.0.0' }] }],
              },
            ],
          }] : [],
        })),
      });

      const report = generateReport(scanResult);

      // 1. Project details
      assert.ok(report.project);
      assert.equal(report.project.name, 'simple-project');
      assert.equal(report.project.version, '1.0.0');
      assert.equal(report.project.status, 'complete');
      assert.ok(report.scan);
      assert.equal(report.scan.tool, 'npm-sbom-tool');
      assert.equal(report.scan.status, 'complete');

      // 2. Component statistics
      assert.ok(report.components);
      assert.equal(report.components.total, 2);
      assert.equal(report.components.direct, 1);
      assert.equal(report.components.transitive, 1);
      assert.equal(report.components.workspace, 0);

      // 3. Vulnerability summary
      assert.ok(report.vulnerabilities);
      assert.equal(report.vulnerabilities.status, 'completed');
      assert.equal(report.vulnerabilities.summary.total, 1);
      assert.equal(report.vulnerabilities.summary.high, 1);
      assert.equal(report.vulnerabilities.summary.critical, 0);
      assert.equal(report.vulnerabilities.summary.medium, 0);
      assert.equal(report.vulnerabilities.summary.low, 0);
      assert.equal(report.vulnerabilities.summary.unknown, 0);

      // 4. Anomaly summary
      assert.ok(report.anomalies);
      assert.equal(report.anomalies.status, 'completed');
      assert.equal(typeof report.anomalies.total, 'number');
      assert.ok(report.anomalies.summary);
      assert.equal(typeof report.anomalies.summary.total, 'number');
      assert.ok(report.anomalies.summary.bySeverity);
      assert.ok(report.anomalies.summary.byType);

      // 5. Dependency comparison (null when not provided)
      assert.equal(report.comparison, null);

      // 6. Overall status and metadata
      assert.equal(report.status, 'complete');
      assert.ok(report.sbom);
      assert.equal(report.sbom.format, 'CycloneDX');
      assert.equal(report.sbom.specVersion, '1.7');
      assert.equal(report.validation.valid, true);
    });

    it('correctly includes dependency comparison results when available', () => {
      const mockComparison = {
        status: 'completed',
        summary: { added: 1, removed: 0, changed: 2, unchanged: 5 },
        added: [{ name: 'pkg-new', version: '1.0.0', changeType: 'added' }],
        removed: [],
        changed: [{ name: 'pkg-up', previousVersion: '1.0.0', currentVersion: '2.0.0', changeType: 'upgrade' }],
        unchanged: [],
      };

      const mockScanResult = {
        status: 'complete',
        projectMetadata: { name: 'app', version: '2.0.0' },
        projectPath: '/test/app',
        components: [
          { name: 'app', isRoot: true },
          { name: 'dep-a', dependencyType: 'direct' },
        ],
        comparison: mockComparison,
      };

      const report = generateReport(mockScanResult);
      assert.ok(report.comparison);
      assert.equal(report.comparison.status, 'completed');
      assert.equal(report.comparison.summary.added, 1);
      assert.equal(report.comparison.summary.changed, 2);
      assert.equal(report.comparison.added.length, 1);
      assert.equal(report.comparison.changed.length, 1);
    });

    it('accurately reports zero-dependency projects', async () => {
      const scanResult = await executeScan(zeroDepsPath);
      const report = generateReport(scanResult);

      assert.equal(report.status, 'complete');
      assert.equal(report.components.total, 0);
      assert.equal(report.components.direct, 0);
      assert.equal(report.components.transitive, 0);
      assert.equal(report.components.workspace, 0);
      assert.equal(report.sbom.componentsCount, 0);
    });
  });

  // ========================================================
  // 3. Edge Cases: Empty Results vs Skipped vs Failed
  // ========================================================
  describe('Edge Cases & State Differentiation', () => {
    it('distinguishes successful vulnerability analysis with zero findings from skipped analysis', () => {
      // Case A: Successful analysis with 0 findings
      const scanWithZeroVulns = {
        status: 'complete',
        projectMetadata: { name: 'clean-app', version: '1.0.0' },
        components: [],
        vulnerabilities: {
          status: 'completed',
          scannedPackages: 5,
          totalPackages: 5,
          vulnerablePackages: 0,
          findings: [],
        },
      };

      const reportZero = generateReport(scanWithZeroVulns);
      assert.ok(reportZero.vulnerabilities);
      assert.equal(reportZero.vulnerabilities.status, 'completed');
      assert.equal(reportZero.vulnerabilities.summary.total, 0);

      // Case B: Analysis skipped (not requested)
      const scanSkipped = {
        status: 'complete',
        projectMetadata: { name: 'skipped-app', version: '1.0.0' },
        components: [],
        vulnerabilities: null,
      };

      const reportSkipped = generateReport(scanSkipped);
      assert.equal(reportSkipped.vulnerabilities, null);
    });

    it('distinguishes successful anomaly detection with zero findings from skipped detection', () => {
      // Case A: 0 anomalies
      const scanWithZeroAnomalies = {
        status: 'complete',
        projectMetadata: { name: 'valid-app', version: '1.0.0' },
        components: [],
        anomalies: {
          findings: [],
          summary: { total: 0, bySeverity: { error: 0, warning: 0, info: 0 }, byType: {} },
        },
      };

      const reportZero = generateReport(scanWithZeroAnomalies);
      assert.ok(reportZero.anomalies);
      assert.equal(reportZero.anomalies.status, 'completed');
      assert.equal(reportZero.anomalies.total, 0);

      // Case B: Anomalies skipped
      const scanSkipped = {
        status: 'complete',
        projectMetadata: { name: 'skipped-app', version: '1.0.0' },
        components: [],
        anomalies: null,
      };

      const reportSkipped = generateReport(scanSkipped);
      assert.equal(reportSkipped.anomalies, null);
    });

    it('preserves component statistics and partial status on partial scans', async () => {
      const scanResult = await executeScan(missingLockfilePath);
      const report = generateReport(scanResult);

      assert.equal(report.status, 'partial');
      assert.equal(report.sbom, null);
      assert.equal(report.vulnerabilities, null);
      assert.equal(report.anomalies, null);
      assert.equal(report.comparison, null);

      // Manifest dependencies are still counted in components statistics
      assert.ok(report.components.total > 0);
      assert.ok(report.components.direct > 0);
    });

    it('handles failed scans safely without throwing', () => {
      const failedScan = {
        status: 'failed',
        projectMetadata: null,
        projectPath: '/nonexistent',
        errors: [{ code: 'PROJECT_NOT_FOUND', message: 'Target path does not exist' }],
        warnings: [],
        components: [],
        bom: null,
        validation: null,
        vulnerabilities: null,
        anomalies: null,
        comparison: null,
      };

      const report = generateReport(failedScan);
      assert.equal(report.status, 'failed');
      assert.equal(report.project.name, 'nonexistent');
      assert.equal(report.components.total, 0);
      assert.equal(report.sbom, null);
      assert.equal(report.errors.length, 1);
      assert.equal(report.errors[0].code, 'PROJECT_NOT_FOUND');
    });

    it('isolates vulnerability analysis failure without marking overall SBOM scan as failed', () => {
      const scanWithFailedVuln = {
        status: 'complete',
        projectMetadata: { name: 'app', version: '1.0.0' },
        bom: { bomFormat: 'CycloneDX', specVersion: '1.7', components: [], dependencies: [] },
        validation: { valid: true, errors: [], warnings: [] },
        components: [{ name: 'app', isRoot: true }],
        vulnerabilities: {
          status: 'failed',
          scannedPackages: 0,
          totalPackages: 1,
          vulnerablePackages: 0,
          findings: [],
          errors: [{ package: { name: 'dep' }, error: 'Network error', code: 'NETWORK_ERROR' }],
        },
        anomalies: {
          findings: [],
          summary: { total: 0, bySeverity: { error: 0, warning: 0, info: 0 }, byType: {} },
        },
      };

      const report = generateReport(scanWithFailedVuln);
      assert.equal(report.status, 'complete');
      assert.ok(report.sbom);
      assert.equal(report.vulnerabilities.status, 'failed');
      assert.equal(report.anomalies.status, 'completed');
    });
  });

  // ========================================================
  // 4. Output Files Generation (generateReportFiles)
  // ========================================================
  describe('generateReportFiles Four Output Files', () => {
    it('generates all four files with valid JSON for a complete scan', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'order19-files-'));
      const scanResult = await executeScan(simplePath, {
        full: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
      });

      try {
        const written = generateReportFiles(tmpDir, scanResult);

        // 1. sbom.json
        assert.ok(written.sbom);
        assert.ok(fs.existsSync(written.sbom));
        const sbom = JSON.parse(fs.readFileSync(written.sbom, 'utf8'));
        assert.equal(sbom.bomFormat, 'CycloneDX');
        assert.equal(validateStructure(sbom).valid, true);

        // 2. vulnerabilities.json
        assert.ok(written.vulnerabilities);
        assert.ok(fs.existsSync(written.vulnerabilities));
        const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
        assert.equal(vulns.status, 'completed');
        assert.ok(Array.isArray(vulns.findings));

        // 3. anomalies.json
        assert.ok(written.anomalies);
        assert.ok(fs.existsSync(written.anomalies));
        const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
        assert.equal(anomalies.status, 'completed');
        assert.ok(Array.isArray(anomalies.findings));

        // 4. report.json
        assert.ok(written.report);
        assert.ok(fs.existsSync(written.report));
        const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
        assert.equal(report.status, 'complete');
        assert.equal(report.project.name, 'simple-project');
        assert.ok(report.components);
        assert.ok(report.vulnerabilities);
        assert.ok(report.anomalies);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('writes skipped notice in vulnerabilities.json and anomalies.json when not performed', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'order19-skipped-'));
      const scanWithoutAnalyses = {
        status: 'complete',
        projectMetadata: { name: 'basic-app', version: '1.0.0' },
        bom: { bomFormat: 'CycloneDX', specVersion: '1.7', components: [], dependencies: [] },
        validation: { valid: true, errors: [], warnings: [] },
        components: [],
        vulnerabilities: null,
        anomalies: null,
      };

      try {
        const written = generateReportFiles(tmpDir, scanWithoutAnalyses);

        const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
        assert.equal(vulns.status, 'skipped');
        assert.ok(vulns.reason.includes('not requested'));

        const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
        assert.equal(anomalies.status, 'skipped');
        assert.ok(anomalies.reason.includes('not requested'));

        const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
        assert.equal(report.vulnerabilities, null);
        assert.equal(report.anomalies, null);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('does not write sbom.json for partial scan and writes partial report.json', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'order19-part-'));
      const scanResult = await executeScan(missingLockfilePath);

      try {
        const written = generateReportFiles(tmpDir, scanResult);

        assert.equal(written.sbom, undefined);
        assert.equal(fs.existsSync(path.join(tmpDir, 'sbom.json')), false);

        assert.ok(fs.existsSync(written.vulnerabilities));
        const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
        assert.equal(vulns.status, 'skipped');

        assert.ok(fs.existsSync(written.anomalies));
        const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
        assert.equal(anomalies.status, 'skipped');

        assert.ok(fs.existsSync(written.report));
        const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
        assert.equal(report.status, 'partial');
        assert.equal(report.sbom, null);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  // ========================================================
  // 5. Backward Compatibility with Order 18
  // ========================================================
  describe('Backward Compatibility', () => {
    it('aliases buildCombinedReport to generateReport', () => {
      assert.equal(buildCombinedReport, generateReport);
    });

    it('aliases writeMultiFileOutput to generateReportFiles', () => {
      assert.equal(writeMultiFileOutput, generateReportFiles);
    });
  });

  // ========================================================
  // 6. Order 19 Audit Regression Tests
  // ========================================================
  describe('Audit Regression: Bug Fixes', () => {
    it('computeSeverityCounts handles numeric severity scores without throwing', () => {
      const findings = [
        { id: 'V1', severity: { score: 9.5 } },
        { id: 'V2', severity: { score: 7.2 } },
        { id: 'V3', severity: { score: 5.0 } },
        { id: 'V4', severity: { score: 2.5 } },
        { id: 'V5', severity: { score: 0 } },
      ];

      const counts = computeSeverityCounts(findings);
      assert.equal(counts.critical, 1);
      assert.equal(counts.high, 1);
      assert.equal(counts.medium, 1);
      assert.equal(counts.low, 1);
      assert.equal(counts.unknown, 1);
    });

    it('generateReport excludes sbom section when bom exists but validation fails', () => {
      const scanResult = {
        status: 'complete',
        projectMetadata: { name: 'test-app', version: '1.0.0' },
        projectPath: '/test',
        components: [],
        bom: { bomFormat: 'CycloneDX', specVersion: '1.7', components: [], dependencies: [] },
        validation: { valid: false, errors: ['Missing required field'], warnings: [] },
        vulnerabilities: null,
        anomalies: null,
      };

      const report = generateReport(scanResult);
      assert.equal(report.sbom, null, 'sbom section must be null when validation.valid is false');
    });

    it('generateReport defensive copies errors and warnings arrays', () => {
      const scanResult = {
        status: 'complete',
        projectMetadata: { name: 'test', version: '1.0.0' },
        projectPath: '/test',
        components: [],
        errors: [{ code: 'TEST_ERR', message: 'err' }],
        warnings: [{ code: 'TEST_WARN', message: 'warn' }],
      };

      const report = generateReport(scanResult);
      assert.notEqual(report.errors, scanResult.errors);
      assert.notEqual(report.warnings, scanResult.warnings);
      report.warnings.push({ code: 'MUTATED', message: 'mutated' });
      assert.equal(scanResult.warnings.length, 1);
    });
  });
});
