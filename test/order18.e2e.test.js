import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  executeScan,
  executeSbom,
  executeAudit,
  buildCombinedReport,
  writeMultiFileOutput,
  validateStructure,
} from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cliScriptPath = path.join(__dirname, '..', 'src', 'cli.js');
const fixturesDir = path.join(__dirname, '..', 'fixtures');
const simplePath = path.join(fixturesDir, 'simple-project');
const missingLockfilePath = path.join(fixturesDir, 'missing-lockfile-project');

// Temporary directory for mock loaders
const tempLoaderDir = fs.mkdtempSync(path.join(os.tmpdir(), 'order18-test-loaders-'));
const defaultMockLoaderPath = path.join(tempLoaderDir, 'defaultMockLoader.js');

// Mock loader that returns empty vulnerabilities (zero-network)
fs.writeFileSync(
  defaultMockLoaderPath,
  `globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ vulns: [] })
  });`,
  'utf8'
);

// Mock loader that simulates network failure
const failMockLoaderPath = path.join(tempLoaderDir, 'failMockLoader.js');
fs.writeFileSync(
  failMockLoaderPath,
  `globalThis.fetch = async () => {
    throw new Error('ECONNREFUSED mock network failure');
  };`,
  'utf8'
);

describe('Order 18: Engine Integration and Full Scan Workflow', () => {

  // ========================================================
  // 1. Engine API Tests
  // ========================================================
  describe('Engine APIs', () => {
    it('executeScan runs complete scan with options', async () => {
      const result = await executeScan(simplePath, {
        vulnerabilities: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
      });

      assert.equal(result.status, 'complete');
      assert.ok(result.bom);
      assert.ok(result.validation?.valid);
      assert.ok(result.anomalies);
      assert.ok(result.vulnerabilities);
    });

    it('executeSbom runs SBOM generation without vulnerabilities or anomalies', async () => {
      const result = await executeSbom(simplePath);

      assert.equal(result.success, true);
      assert.equal(result.status, 'complete');
      assert.ok(result.bom);
      assert.equal(result.bom.bomFormat, 'CycloneDX');
      assert.equal(result.bom.specVersion, '1.7');
      assert.ok(result.validation?.valid);
    });

    it('executeSbom returns clean failure on partial scan projects', async () => {
      const result = await executeSbom(missingLockfilePath);

      assert.equal(result.success, false);
      assert.equal(result.bom, null);
      assert.ok(result.message.includes('package-lock.json is required'));
    });

    it('executeAudit distinguishes vulnerabilities from anomalies and supports comparison', async () => {
      const prev = await executeScan(simplePath);
      const audit = await executeAudit(simplePath, {
        previousSbom: prev.bom,
        queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
      });

      assert.equal(audit.success, true);
      assert.ok(audit.project);
      assert.ok(audit.summary);
      assert.ok(audit.vulnerabilities);
      assert.ok(audit.anomalies);
      assert.ok(audit.comparison);
      assert.equal(audit.comparison.status, 'completed');
    });

    it('buildCombinedReport builds uniform report conforming to specification', async () => {
      const scanResult = await executeScan(simplePath, {
        full: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
      });

      const report = buildCombinedReport(scanResult);

      assert.ok(report.scan);
      assert.equal(report.scan.tool, 'npm-sbom-tool');
      assert.equal(report.scan.status, 'complete');
      assert.ok(report.project);
      assert.equal(report.project.name, 'simple-project');
      assert.ok(report.sbom);
      assert.equal(report.sbom.format, 'CycloneDX');
      assert.equal(report.sbom.specVersion, '1.7');
      assert.ok(report.validation?.valid);
      assert.ok(report.vulnerabilities);
      assert.ok(report.anomalies);
      assert.equal(report.comparison, null);
      assert.equal(report.status, 'complete');
    });

    it('writeMultiFileOutput writes the 4 report files with valid JSON', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'order18-multifile-'));
      const scanResult = await executeScan(simplePath, {
        full: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
      });

      try {
        const written = writeMultiFileOutput(tmpDir, scanResult);

        assert.ok(written.sbom);
        assert.ok(written.vulnerabilities);
        assert.ok(written.anomalies);
        assert.ok(written.report);

        // Verify all 4 files exist and parse as valid JSON
        const sbomContent = JSON.parse(fs.readFileSync(written.sbom, 'utf8'));
        assert.equal(sbomContent.bomFormat, 'CycloneDX');
        assert.equal(validateStructure(sbomContent).valid, true);

        const vulnContent = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
        assert.equal(vulnContent.status, 'completed');
        assert.ok(Array.isArray(vulnContent.findings));

        const anomalyContent = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
        assert.equal(anomalyContent.status, 'completed');
        assert.ok(Array.isArray(anomalyContent.findings));

        const reportContent = JSON.parse(fs.readFileSync(written.report, 'utf8'));
        assert.equal(reportContent.status, 'complete');
        assert.equal(reportContent.project.name, 'simple-project');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  // ========================================================
  // 2. CLI End-to-End Tests
  // ========================================================
  describe('CLI End-to-End --full Workflow', () => {
    it('1. complete scan using scan --full generates output directory with 4 JSON files', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-test-'));
      const outputDir = path.join(tmpDir, 'scan-output');

      try {
        const stdout = execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', simplePath, '--full', '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );

        assert.ok(stdout.includes('Scanning project:'));
        assert.ok(stdout.includes('Scan status: complete'));
        assert.ok(stdout.includes('--- Vulnerability Analysis ---'));
        assert.ok(stdout.includes('--- Anomaly Detection ---'));
        assert.ok(stdout.includes('Generated report files in:'));

        const sbomPath = path.join(outputDir, 'sbom.json');
        const vulnPath = path.join(outputDir, 'vulnerabilities.json');
        const anomalyPath = path.join(outputDir, 'anomalies.json');
        const reportPath = path.join(outputDir, 'report.json');

        assert.ok(fs.existsSync(sbomPath), 'sbom.json must exist');
        assert.ok(fs.existsSync(vulnPath), 'vulnerabilities.json must exist');
        assert.ok(fs.existsSync(anomalyPath), 'anomalies.json must exist');
        assert.ok(fs.existsSync(reportPath), 'report.json must exist');

        const bom = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));
        assert.equal(bom.bomFormat, 'CycloneDX');
        assert.equal(validateStructure(bom).valid, true);

        const vulns = JSON.parse(fs.readFileSync(vulnPath, 'utf8'));
        assert.equal(vulns.status, 'completed');

        const anomalies = JSON.parse(fs.readFileSync(anomalyPath, 'utf8'));
        assert.equal(anomalies.status, 'completed');

        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        assert.equal(report.status, 'complete');
        assert.equal(report.scan.tool, 'npm-sbom-tool');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('2. scan --full with --output directory argument creates the directory and writes files', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-out-'));
      const outputDir = path.join(tmpDir, 'custom-reports');

      try {
        execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', simplePath, '--full', '-o', outputDir
          ],
          { encoding: 'utf8' }
        );

        assert.ok(fs.existsSync(path.join(outputDir, 'sbom.json')));
        assert.ok(fs.existsSync(path.join(outputDir, 'vulnerabilities.json')));
        assert.ok(fs.existsSync(path.join(outputDir, 'anomalies.json')));
        assert.ok(fs.existsSync(path.join(outputDir, 'report.json')));
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('3. scan --full with --json outputs combined report JSON directly to stdout', () => {
      const stdout = execFileSync(
        process.execPath,
        [
          '--import', `file://${defaultMockLoaderPath}`,
          cliScriptPath, 'scan', simplePath, '--full', '--json'
        ],
        { encoding: 'utf8' }
      );

      const parsed = JSON.parse(stdout);
      assert.equal(parsed.status, 'complete');
      assert.ok(parsed.scan);
      assert.equal(parsed.scan.tool, 'npm-sbom-tool');
      assert.ok(parsed.project);
      assert.ok(parsed.sbom);
      assert.equal(parsed.sbom.format, 'CycloneDX');
      assert.ok(parsed.vulnerabilities);
      assert.ok(parsed.anomalies);
      assert.equal(parsed.comparison, null);
    });

    it('4. scan --full with --previous-sbom performs comparison and includes it in report.json', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-prev-'));
      const prevBomPath = path.join(tmpDir, 'prev.cdx.json');
      const outputDir = path.join(tmpDir, 'out');

      // Create a mock previous CycloneDX SBOM
      const mockPrev = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: { component: { name: 'simple-project', version: '1.0.0', 'bom-ref': 'root' } },
        components: [
          { name: 'is-odd', version: '0.1.0', 'bom-ref': 'pkg:npm/is-odd@0.1.0', purl: 'pkg:npm/is-odd@0.1.0' }
        ],
        dependencies: []
      };
      fs.writeFileSync(prevBomPath, JSON.stringify(mockPrev), 'utf8');

      try {
        const stdout = execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', simplePath, '--full',
            '--previous-sbom', prevBomPath,
            '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );

        assert.ok(stdout.includes('--- Dependency Comparison ---'));

        const report = JSON.parse(fs.readFileSync(path.join(outputDir, 'report.json'), 'utf8'));
        assert.ok(report.comparison, 'comparison should be included in report.json');
        assert.equal(report.comparison.status, 'completed');
        assert.ok(report.comparison.summary);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('5. scan --full gracefully handles OSV API network failure without invalidating SBOM', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-fail-'));
      const outputDir = path.join(tmpDir, 'fail-out');

      try {
        const stdout = execFileSync(
          process.execPath,
          [
            '--import', `file://${failMockLoaderPath}`,
            cliScriptPath, 'scan', simplePath, '--full', '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );

        assert.ok(stdout.includes('Scan status: complete'));
        assert.ok(stdout.includes('Status: FAILED'));

        // sbom.json is still generated and valid!
        const sbomPath = path.join(outputDir, 'sbom.json');
        assert.ok(fs.existsSync(sbomPath));
        const bom = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));
        assert.equal(validateStructure(bom).valid, true);

        // vulnerabilities.json reflects the failure
        const vulnPath = path.join(outputDir, 'vulnerabilities.json');
        const vulns = JSON.parse(fs.readFileSync(vulnPath, 'utf8'));
        assert.equal(vulns.status, 'failed');

        // report.json reflects scan complete with failed vuln check
        const reportPath = path.join(outputDir, 'report.json');
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        assert.equal(report.status, 'complete');
        assert.equal(report.vulnerabilities.status, 'failed');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('6. scan --full handles partial scan project and writes report.json without invalid SBOM', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-part-'));
      const outputDir = path.join(tmpDir, 'part-out');

      try {
        const stdout = execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', missingLockfilePath, '--full', '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );

        assert.ok(stdout.includes('Scan status: partial'));

        // sbom.json is NOT generated for partial scan
        assert.equal(fs.existsSync(path.join(outputDir, 'sbom.json')), false);

        // report.json is generated with partial status
        const reportPath = path.join(outputDir, 'report.json');
        assert.ok(fs.existsSync(reportPath));
        const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        assert.equal(report.status, 'partial');
        assert.equal(report.sbom, null);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('7. audit command supports --previous-sbom flag', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-audit-prev-'));
      const prevBomPath = path.join(tmpDir, 'prev.cdx.json');

      const mockPrev = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [{ name: 'is-odd', version: '0.1.0' }],
      };
      fs.writeFileSync(prevBomPath, JSON.stringify(mockPrev), 'utf8');

      try {
        const stdout = execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'audit', simplePath, '--previous-sbom', prevBomPath, '--json'
          ],
          { encoding: 'utf8' }
        );

        const report = JSON.parse(stdout);
        assert.ok(report.comparison);
        assert.equal(report.comparison.status, 'completed');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('8. scan command accepts --anomalies and -a flags explicitly', () => {
      const stdout = execFileSync(
        process.execPath,
        [cliScriptPath, 'scan', simplePath, '--anomalies'],
        { encoding: 'utf8' }
      );

      assert.ok(stdout.includes('--- Anomaly Detection ---'));
    });

    it('9. fails with code 1 when --full is used on sbom command', () => {
      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'sbom', simplePath, '--full'], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        assert.ok(err.stderr.includes('Unknown option "--full"'));
        return true;
      });
    });

    it('10. running --full twice in same output directory prevents stale sbom.json on subsequent partial scan', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-stale-'));
      const outputDir = path.join(tmpDir, 'reports');

      try {
        // Run 1: Complete scan generates sbom.json
        execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', simplePath, '--full', '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );
        const sbomPath = path.join(outputDir, 'sbom.json');
        assert.ok(fs.existsSync(sbomPath), 'Run 1 must generate sbom.json');

        // Run 2: Partial scan in the same output directory
        execFileSync(
          process.execPath,
          [
            '--import', `file://${defaultMockLoaderPath}`,
            cliScriptPath, 'scan', missingLockfilePath, '--full', '--output-dir', outputDir
          ],
          { encoding: 'utf8' }
        );

        // Stale sbom.json from Run 1 MUST be cleaned up so consumer does not see mismatched SBOM
        assert.equal(fs.existsSync(sbomPath), false, 'Stale sbom.json must be removed on subsequent partial scan');

        const report = JSON.parse(fs.readFileSync(path.join(outputDir, 'report.json'), 'utf8'));
        assert.equal(report.status, 'partial');
        assert.equal(report.sbom, null);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('11. handles output directory creation/writing failures cleanly with exit code 1', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-err-'));
      // Create a file where a directory is expected for --output-dir
      const blockingFile = path.join(tmpDir, 'blocking-file');
      fs.writeFileSync(blockingFile, 'hello', 'utf8');
      const badOutputDir = path.join(blockingFile, 'sub-dir');

      try {
        assert.throws(() => {
          execFileSync(
            process.execPath,
            [
              '--import', `file://${defaultMockLoaderPath}`,
              cliScriptPath, 'scan', simplePath, '--full', '--output-dir', badOutputDir
            ],
            { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
          );
        }, (err) => {
          assert.equal(err.status, 1);
          assert.ok(err.stderr.includes('Failed to write output directory'));
          return true;
        });
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('12. reports warning if stale SBOM cleanup deletion fails instead of silently ignoring', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-full-del-err-'));
      const sbomPath = path.join(tmpDir, 'sbom.json');
      fs.writeFileSync(sbomPath, '{"fake": true}', 'utf8');

      const fakeScanResult = {
        status: 'partial',
        bom: null,
        validation: null,
        warnings: [],
        errors: [],
        components: [],
      };

      const originalRmSync = fs.rmSync;
      try {
        fs.rmSync = (targetPath, opts) => {
          if (targetPath === sbomPath) {
            throw new Error('EPERM: operation not permitted');
          }
          return originalRmSync(targetPath, opts);
        };

        const written = writeMultiFileOutput(tmpDir, fakeScanResult);
        assert.ok(written.cleanupWarning, 'Must return cleanupWarning if deletion fails');
        assert.ok(written.cleanupWarning.message.includes('Failed to remove stale sbom.json'));
        assert.ok(fakeScanResult.warnings.some(w => w.message.includes('Failed to remove stale sbom.json')));

        const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
        assert.ok(report.warnings.some(w => w.message.includes('Failed to remove stale sbom.json')));
      } finally {
        fs.rmSync = originalRmSync;
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });
});

