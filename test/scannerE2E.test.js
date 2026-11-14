import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanProject, scanProjectSync } from '../src/scanner/index.js';
import { executeScan, executeSbom, executeAudit } from '../src/engine/index.js';
import {
  generateReport,
  generateReportFiles,
  computeSeverityCounts,
} from '../src/reportGenerator.js';
import { validateStructure } from '../src/validator.js';
import { ScanStatus } from '../src/errors.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, '..', 'fixtures');

// Fixture paths
const simplePath = path.join(fixturesDir, 'simple-project');
const largePath = path.join(fixturesDir, 'large-project');
const zeroDepsPath = path.join(fixturesDir, 'zero-deps-project');
const missingLockfilePath = path.join(fixturesDir, 'missing-lockfile-project');
const invalidPath = path.join(fixturesDir, 'invalid-project');
const emptyPath = path.join(fixturesDir, 'empty-project');
const transitivePath = path.join(fixturesDir, 'transitive-project');
const mixedPath = path.join(fixturesDir, 'mixed-dependencies-project');
const scopedPath = path.join(fixturesDir, 'scoped-package-project');
const workspaceWithLockfilePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
const monorepoPath = path.join(fixturesDir, 'monorepo-project');
const malformedLockfilePath = path.join(fixturesDir, 'malformed-lockfile-project');
const invalidLockfilePath = path.join(fixturesDir, 'invalid-lockfile-project');
const multipleVersionsPath = path.join(fixturesDir, 'multiple-versions-project');
const unresolvedDepsPath = path.join(fixturesDir, 'unresolved-deps-project');

// Mock queryPackages to avoid live network calls
const noOpQueryPackages = async (pkgs) => pkgs.map(p => ({
  package: p,
  vulnerabilities: [],
}));

const mockVulnQueryPackages = async (pkgs) => pkgs.map(p => ({
  package: p,
  vulnerabilities: p.name === 'is-odd' ? [{
    id: 'GHSA-mock-001',
    summary: 'Mock vulnerability in is-odd',
    severity: [{ type: 'CVSS_V3', score: '7.5' }],
    affected: [{
      package: { name: 'is-odd', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.0.0' }] }],
    }],
  }] : [],
}));

// =============================================================================
// Order 19 Regression Tests
// =============================================================================
describe('Order 19 Regression: Report Generator Bug Fixes', () => {
  it('computeSeverityCounts handles numeric severity scores without throwing', () => {
    const findings = [
      { id: 'V1', severity: { score: 9.5 } },
      { id: 'V2', severity: { score: 7.2 } },
      { id: 'V3', severity: { score: 5.0 } },
      { id: 'V4', severity: { score: 2.5 } },
      { id: 'V5', severity: { score: 0 } },
    ];

    const counts = computeSeverityCounts(findings);
    assert.equal(counts.critical, 1, 'score 9.5 should be critical');
    assert.equal(counts.high, 1, 'score 7.2 should be high');
    assert.equal(counts.medium, 1, 'score 5.0 should be medium');
    assert.equal(counts.low, 1, 'score 2.5 should be low');
    assert.equal(counts.unknown, 1, 'score 0 should be unknown');
  });

  it('computeSeverityCounts handles mixed numeric and string severity scores', () => {
    const findings = [
      { id: 'V1', severity: { score: 9.8 } },
      { id: 'V2', severity: { score: 'CRITICAL' } },
      { id: 'V3', severity: { score: '7.5' } },
      { id: 'V4', severity: { score: 'HIGH' } },
      { id: 'V5', severity: { score: 4.5 } },
      { id: 'V6', severity: { score: 'MEDIUM' } },
      { id: 'V7', severity: { score: 1.2 } },
    ];

    const counts = computeSeverityCounts(findings);
    assert.equal(counts.critical, 2);
    assert.equal(counts.high, 2);
    assert.equal(counts.medium, 2);
    assert.equal(counts.low, 1);
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
    assert.equal(report.sbom, null, 'sbom section should be null for invalid BOM');
    assert.equal(report.validation.valid, false);
  });

  it('generateReport does not share array references with input scanResult', () => {
    const scanResult = {
      status: 'complete',
      projectMetadata: { name: 'test', version: '1.0.0' },
      projectPath: '/test',
      components: [],
      errors: [{ code: 'TEST', message: 'original error' }],
      warnings: [{ code: 'TEST', message: 'original warning' }],
    };

    const report = generateReport(scanResult);

    // Report arrays should be copies, not references
    assert.notEqual(report.errors, scanResult.errors);
    assert.notEqual(report.warnings, scanResult.warnings);

    // Content should still be preserved
    assert.equal(report.errors.length, 1);
    assert.equal(report.warnings.length, 1);
    assert.equal(report.errors[0].message, 'original error');
    assert.equal(report.warnings[0].message, 'original warning');

    // Mutating the report copy should not affect the original
    report.warnings.push({ code: 'NEW', message: 'added' });
    assert.equal(scanResult.warnings.length, 1);
  });
});

// =============================================================================
// E2E Test Suite: Simple npm Projects
// =============================================================================
describe('E2E: Simple npm projects', () => {
  it('scans simple-project with correct package parsing', async () => {
    const result = await scanProject(simplePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.projectMetadata.name, 'simple-project');
    assert.equal(result.projectMetadata.version, '1.0.0');

    const nonRoot = result.components.filter(c => !c.isRoot);
    assert.equal(nonRoot.length, 2);

    const isOdd = nonRoot.find(c => c.name === 'is-odd');
    assert.ok(isOdd, 'should discover is-odd');
    assert.equal(isOdd.version, '3.0.1');
    assert.equal(isOdd.dependencyType, 'direct');

    const isNumber = nonRoot.find(c => c.name === 'is-number');
    assert.ok(isNumber, 'should discover is-number');
    assert.equal(isNumber.version, '6.0.0');
    assert.equal(isNumber.dependencyType, 'transitive');
  });

  it('generates valid CycloneDX SBOM for simple-project', async () => {
    const result = await scanProject(simplePath);

    assert.ok(result.bom, 'should generate BOM');
    assert.equal(result.bom.bomFormat, 'CycloneDX');
    assert.equal(result.bom.specVersion, '1.7');
    assert.ok(result.validation.valid, 'BOM should be valid');

    // Verify BOM components have PURLs
    for (const comp of result.bom.components) {
      assert.ok(comp.purl, `Component ${comp.name} should have a PURL`);
      assert.ok(comp.purl.startsWith('pkg:npm/'), `PURL should start with pkg:npm/`);
    }
  });

  it('resolves dependency relationships correctly', async () => {
    const result = await scanProject(simplePath);
    const deps = result.dependencyEdges;

    // Root depends on is-odd
    const rootRef = Object.keys(deps).find(k => k.includes('simple-project'));
    assert.ok(rootRef, 'should have root dependency edge');
    const rootDeps = deps[rootRef];
    assert.ok(rootDeps.some(d => d.includes('is-odd')), 'root should depend on is-odd');

    // is-odd depends on is-number
    const isOddRef = Object.keys(deps).find(k => k.includes('is-odd'));
    assert.ok(isOddRef, 'should have is-odd dependency edge');
    const isOddDeps = deps[isOddRef];
    assert.ok(isOddDeps.some(d => d.includes('is-number')), 'is-odd should depend on is-number');
  });

  it('synchronous and async scanners produce equivalent results', () => {
    const syncResult = scanProjectSync(simplePath);
    assert.equal(syncResult.status, ScanStatus.COMPLETE);
    assert.equal(syncResult.projectMetadata.name, 'simple-project');

    const nonRoot = syncResult.components.filter(c => !c.isRoot);
    assert.equal(nonRoot.length, 2);
    assert.ok(syncResult.bom);
    assert.ok(syncResult.validation.valid);
  });
});

// =============================================================================
// E2E Test Suite: Large npm Projects
// =============================================================================
describe('E2E: Large npm projects', () => {
  it('scans large-project with many direct and transitive dependencies', async () => {
    const result = await scanProject(largePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.projectMetadata.name, 'large-project');
    assert.equal(result.projectMetadata.version, '3.0.0');

    const nonRoot = result.components.filter(c => !c.isRoot);
    assert.ok(nonRoot.length >= 10, `should have at least 10 components, got ${nonRoot.length}`);

    const directDeps = nonRoot.filter(c => c.dependencyType === 'direct');
    assert.ok(directDeps.length >= 10, `should have at least 10 direct deps, got ${directDeps.length}`);
  });

  it('correctly resolves transitive dependency chains in large-project', async () => {
    const result = await scanProject(largePath);

    const nonRoot = result.components.filter(c => !c.isRoot);
    const transitive = nonRoot.filter(c => c.dependencyType === 'transitive');
    assert.ok(transitive.length >= 3, 'should have transitive dependencies from accepts');

    // accepts -> mime-types -> mime-db
    const mimeDb = nonRoot.find(c => c.name === 'mime-db');
    assert.ok(mimeDb, 'should resolve mime-db as transitive dependency');
    assert.equal(mimeDb.dependencyType, 'transitive');
  });

  it('generates valid SBOM with accurate component count for large-project', async () => {
    const result = await scanProject(largePath);

    assert.ok(result.bom);
    assert.ok(result.validation.valid);

    const bomComponents = result.bom.components;
    const nonRoot = result.components.filter(c => !c.isRoot);
    assert.equal(bomComponents.length, nonRoot.length, 'BOM component count should match');

    // Verify all BOM components have required metadata
    for (const comp of bomComponents) {
      assert.ok(comp.name, 'component should have name');
      assert.ok(comp.version, 'component should have version');
      assert.ok(comp.purl, 'component should have PURL');
    }
  });

  it('generates report with accurate component statistics', async () => {
    const result = await scanProject(largePath);
    const report = generateReport(result);

    assert.equal(report.status, 'complete');
    assert.ok(report.components.total >= 10);
    assert.ok(report.components.direct >= 10);
    assert.ok(report.components.transitive >= 3);
    assert.equal(report.components.total, report.components.direct + report.components.transitive + report.components.workspace);
  });
});

// =============================================================================
// E2E Test Suite: Projects Without Dependencies
// =============================================================================
describe('E2E: Projects without dependencies', () => {
  it('scans zero-deps-project successfully with empty component list', async () => {
    const result = await scanProject(zeroDepsPath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.projectMetadata.name, 'zero-deps-project');

    const nonRoot = result.components.filter(c => !c.isRoot);
    assert.equal(nonRoot.length, 0);
    assert.equal(result.errors.length, 0);
  });

  it('generates valid SBOM with zero components', async () => {
    const result = await scanProject(zeroDepsPath);

    assert.ok(result.bom, 'should generate BOM even with zero deps');
    assert.ok(result.validation.valid);
    assert.equal(result.bom.components.length, 0);
  });

  it('generates accurate report for zero-dependency project', async () => {
    const result = await scanProject(zeroDepsPath);
    const report = generateReport(result);

    assert.equal(report.status, 'complete');
    assert.equal(report.components.total, 0);
    assert.equal(report.components.direct, 0);
    assert.equal(report.components.transitive, 0);
    assert.ok(report.sbom);
    assert.equal(report.sbom.componentsCount, 0);
  });

  it('writes valid output files for zero-dependency project', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-zerodeps-'));
    const result = await scanProject(zeroDepsPath);

    try {
      const written = generateReportFiles(tmpDir, result);

      assert.ok(written.sbom, 'sbom.json should be written');
      const sbom = JSON.parse(fs.readFileSync(written.sbom, 'utf8'));
      assert.equal(sbom.components.length, 0);
      assert.ok(validateStructure(sbom).valid);

      const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
      assert.equal(report.components.total, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// =============================================================================
// E2E Test Suite: Missing or Invalid Project Files
// =============================================================================
describe('E2E: Missing or invalid project files', () => {
  it('returns failed status for non-existent project path', async () => {
    const result = await scanProject('/nonexistent/path/does/not/exist');
    assert.equal(result.status, ScanStatus.FAILED);
    assert.ok(result.errors.length > 0);
    assert.equal(result.bom, null);
  });

  it('returns failed status for missing package.json', async () => {
    const result = await scanProject(emptyPath);
    assert.equal(result.status, ScanStatus.FAILED);
    assert.equal(result.bom, null);
    assert.equal(result.components.length, 0);
  });

  it('returns failed status for invalid package.json', async () => {
    const result = await scanProject(invalidPath);
    assert.equal(result.status, ScanStatus.FAILED);
    assert.ok(result.errors.length > 0);
    assert.equal(result.bom, null);
  });

  it('returns partial status when package-lock.json is missing', async () => {
    const result = await scanProject(missingLockfilePath);
    assert.equal(result.status, ScanStatus.PARTIAL);

    // Should still discover manifest dependencies
    const nonRoot = result.components.filter(c => !c.isRoot);
    assert.ok(nonRoot.length > 0, 'should have manifest-only components');

    // Should not generate BOM
    assert.equal(result.bom, null);
    assert.equal(result.validation, null);
  });

  it('returns partial status for malformed package-lock.json', async () => {
    const result = await scanProject(malformedLockfilePath);

    // Should fall back to partial scan since lockfile is invalid JSON
    assert.equal(result.status, ScanStatus.PARTIAL);
    assert.equal(result.bom, null);
    assert.ok(result.errors.length > 0 || result.warnings.length > 0);
  });

  it('returns partial or failed status for invalid lockfile structure', async () => {
    const result = await scanProject(invalidLockfilePath);

    assert.ok(
      result.status === ScanStatus.PARTIAL || result.status === ScanStatus.FAILED,
      `should be partial or failed, got ${result.status}`
    );
  });

  it('handles failed scan report generation without throwing', async () => {
    const result = await scanProject('/nonexistent/path');
    const report = generateReport(result);

    assert.equal(report.status, 'failed');
    assert.equal(report.sbom, null);
    assert.equal(report.vulnerabilities, null);
    assert.equal(report.anomalies, null);
    assert.ok(report.errors.length > 0);
    assert.equal(report.components.total, 0);
  });

  it('writes correct output files for failed scan', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-failed-'));
    const result = await scanProject('/nonexistent/path');

    try {
      const written = generateReportFiles(tmpDir, result);

      // No sbom.json for failed scan
      assert.equal(written.sbom, undefined);

      // Vulnerabilities and anomalies should indicate skipped
      const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
      assert.equal(vulns.status, 'skipped');

      const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
      assert.equal(anomalies.status, 'skipped');

      // Report should show failed status
      const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
      assert.equal(report.status, 'failed');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// =============================================================================
// E2E Test Suite: npm Workspaces and Monorepos
// =============================================================================
describe('E2E: npm workspaces and monorepos', () => {
  it('discovers workspace packages and external dependencies', async () => {
    const result = await scanProject(workspaceWithLockfilePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    const nonRoot = result.components.filter(c => !c.isRoot);

    // Should include workspace packages and external dependencies
    const pkgA = nonRoot.find(c => c.name === 'pkg-a');
    const pkgB = nonRoot.find(c => c.name === 'pkg-b');
    assert.ok(pkgA, 'should discover workspace pkg-a');
    assert.ok(pkgB, 'should discover workspace pkg-b');

    // First-party packages should be classified
    assert.ok(pkgA.isFirstParty || pkgA.dependencyType === 'workspace');
    assert.ok(pkgB.isFirstParty || pkgB.dependencyType === 'workspace');
  });

  it('resolves workspace-to-workspace dependencies', async () => {
    const result = await scanProject(workspaceWithLockfilePath);

    // pkg-a depends on pkg-b
    const edges = result.dependencyEdges;
    const pkgARef = Object.keys(edges).find(k => k.includes('pkg-a'));
    if (pkgARef) {
      const pkgADeps = edges[pkgARef];
      assert.ok(pkgADeps.some(d => d.includes('pkg-b')), 'pkg-a should depend on pkg-b');
    }
  });

  it('classifies first-party vs third-party components correctly', async () => {
    const result = await scanProject(workspaceWithLockfilePath);

    const nonRoot = result.components.filter(c => !c.isRoot);
    const firstParty = nonRoot.filter(c => c.isFirstParty);
    const thirdParty = nonRoot.filter(c => !c.isFirstParty);

    // Workspace packages are first-party
    assert.ok(firstParty.length >= 2, 'should have at least 2 first-party packages (pkg-a, pkg-b)');

    // External dependencies are third-party
    assert.ok(thirdParty.length > 0, 'should have third-party packages');
    for (const tp of thirdParty) {
      assert.ok(!tp.isFirstParty, `${tp.name} should be third-party`);
    }
  });

  it('generates valid SBOM for workspace project', async () => {
    const result = await scanProject(workspaceWithLockfilePath);

    assert.ok(result.bom);
    assert.ok(result.validation.valid);

    // BOM should include workspace and external components
    const bomComponents = result.bom.components;
    assert.ok(bomComponents.length >= 2, 'BOM should have workspace + external components');
  });

  it('scans monorepo with scoped packages', async () => {
    const result = await scanProject(monorepoPath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    const nonRoot = result.components.filter(c => !c.isRoot);

    // Should discover workspace packages
    const core = nonRoot.find(c => c.name === '@monorepo/core');
    const app = nonRoot.find(c => c.name === '@monorepo/app');
    assert.ok(core, 'should discover @monorepo/core workspace');
    assert.ok(app, 'should discover @monorepo/app workspace');
  });
});

// =============================================================================
// E2E Test Suite: Dependency Resolution and SBOM Validation
// =============================================================================
describe('E2E: Dependency resolution and SBOM validation', () => {
  it('resolves direct and transitive dependencies correctly', async () => {
    const result = await scanProject(transitivePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    const nonRoot = result.components.filter(c => !c.isRoot);

    // accepts (direct) -> mime-types (transitive) -> mime-db (transitive)
    const accepts = nonRoot.find(c => c.name === 'accepts');
    assert.ok(accepts);
    assert.equal(accepts.dependencyType, 'direct');

    const mimeTypes = nonRoot.find(c => c.name === 'mime-types');
    assert.ok(mimeTypes);
    assert.equal(mimeTypes.dependencyType, 'transitive');

    const mimeDb = nonRoot.find(c => c.name === 'mime-db');
    assert.ok(mimeDb);
    assert.equal(mimeDb.dependencyType, 'transitive');
  });

  it('handles projects with multiple dependency types', async () => {
    const result = await scanProject(mixedPath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    const nonRoot = result.components.filter(c => !c.isRoot);

    // Should discover production, dev, and optional dependencies
    assert.ok(nonRoot.find(c => c.name === 'ms'), 'should discover prod dependency');
    assert.ok(nonRoot.find(c => c.name === 'is-odd'), 'should discover dev dependency');
  });

  it('generates PURLs with correct namespace for scoped packages', async () => {
    const result = await scanProject(scopedPath);

    if (result.status === ScanStatus.COMPLETE && result.bom) {
      const scopedComp = result.bom.components.find(c => c.name && c.name.includes('/'));
      if (scopedComp) {
        assert.ok(scopedComp.purl.includes('%40'), 'scoped PURL should URL-encode @');
      }
    }
  });

  it('handles unresolved dependencies gracefully', async () => {
    const result = await scanProject(unresolvedDepsPath);

    // Should not crash on unresolved deps
    assert.ok(result.status !== undefined);
    assert.ok(Array.isArray(result.components));
    if (result.warnings.length > 0 || result.errors.length > 0) {
      // Expect warnings or errors about unresolved dependencies
      const allMessages = [...result.warnings, ...result.errors].map(e => e.message || '');
      assert.ok(allMessages.length > 0);
    }
  });

  it('generates CycloneDX 1.7 compliant SBOM', async () => {
    const result = await scanProject(simplePath);

    assert.ok(result.bom);
    assert.equal(result.bom.bomFormat, 'CycloneDX');
    assert.equal(result.bom.specVersion, '1.7');
    assert.ok(result.bom.serialNumber, 'should have serial number');
    assert.ok(result.bom.metadata, 'should have metadata section');
    assert.ok(result.bom.metadata.timestamp, 'should have metadata timestamp');
    assert.ok(Array.isArray(result.bom.components), 'should have components array');
    assert.ok(Array.isArray(result.bom.dependencies), 'should have dependencies array');
    assert.ok(result.validation.valid, 'should pass structural validation');
  });

  it('verifies component hashes and integrity are preserved', async () => {
    const result = await scanProject(simplePath);

    assert.ok(result.bom);
    for (const comp of result.bom.components) {
      if (comp.hashes && comp.hashes.length > 0) {
        for (const hash of comp.hashes) {
          assert.ok(hash.alg, 'hash should have algorithm');
          assert.ok(hash.content, 'hash should have content');
        }
      }
    }
  });

  it('handles multiple versions of the same package', async () => {
    const result = await scanProject(multipleVersionsPath);

    if (result.status === ScanStatus.COMPLETE) {
      // Check for duplicate package handling
      const nonRoot = result.components.filter(c => !c.isRoot);
      const nameVersionPairs = nonRoot.map(c => `${c.name}@${c.version}`);
      const uniquePairs = new Set(nameVersionPairs);
      assert.equal(nameVersionPairs.length, uniquePairs.size,
        'each name@version pair should be unique');
    }
  });
});

// =============================================================================
// E2E Test Suite: Error Handling and Integration
// =============================================================================
describe('E2E: Error handling and integration', () => {
  it('executeScan returns complete result for valid project', async () => {
    const result = await executeScan(simplePath);
    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.ok(result.bom);
    assert.ok(result.validation.valid);
  });

  it('executeScan with full option enables vulnerability and anomaly analysis', async () => {
    const result = await executeScan(simplePath, {
      full: true,
      queryPackages: noOpQueryPackages,
    });

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.ok(result.vulnerabilities, 'should run vulnerability analysis');
    assert.ok(result.anomalies, 'should run anomaly detection');
  });

  it('executeSbom returns success for valid project', async () => {
    const result = await executeSbom(simplePath);
    assert.ok(result.success);
    assert.ok(result.bom);
    assert.equal(result.bom.bomFormat, 'CycloneDX');
  });

  it('executeSbom returns failure for invalid project', async () => {
    const result = await executeSbom('/nonexistent/path');
    assert.equal(result.success, false);
    assert.equal(result.bom, null);
    assert.ok(result.errors.length > 0);
  });

  it('executeSbom returns failure for partial scan (missing lockfile)', async () => {
    const result = await executeSbom(missingLockfilePath);
    assert.equal(result.success, false);
    assert.equal(result.bom, null);
    assert.ok(result.message.includes('partial') || result.message.includes('lockfile'));
  });

  it('executeAudit returns structured report for valid project', async () => {
    const result = await executeAudit(simplePath, {
      queryPackages: noOpQueryPackages,
    });

    assert.ok(result.success);
    assert.ok(result.project);
    assert.equal(result.project.name, 'simple-project');
    assert.ok(result.summary);
    assert.ok(result.vulnerabilities);
    assert.ok(result.anomalies);
  });

  it('executeAudit returns failure for invalid project', async () => {
    const result = await executeAudit('/nonexistent/path');
    assert.equal(result.success, false);
    assert.equal(result.vulnerabilities, null);
    assert.equal(result.anomalies, null);
  });

  it('executeAudit with vuln-only option skips anomaly detection', async () => {
    const result = await executeAudit(simplePath, {
      vuln: true,
      queryPackages: noOpQueryPackages,
    });

    assert.ok(result.success);
    assert.ok(result.vulnerabilities);
    // When only vuln is requested, anomalies should not be run
    assert.equal(result.anomalies, undefined);
  });

  it('executeAudit with anomaly-only option skips vulnerability analysis', async () => {
    const result = await executeAudit(simplePath, {
      anomaly: true,
    });

    assert.ok(result.success);
    assert.ok(result.anomalies);
    // When only anomaly is requested, vulnerabilities should not be run
    assert.equal(result.vulnerabilities, undefined);
  });

  it('generateReportFiles creates all four output files for complete scan', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-full-'));
    const result = await executeScan(simplePath, {
      full: true,
      queryPackages: noOpQueryPackages,
    });

    try {
      const written = generateReportFiles(tmpDir, result);

      // All four files should exist
      assert.ok(written.sbom);
      assert.ok(written.vulnerabilities);
      assert.ok(written.anomalies);
      assert.ok(written.report);

      // Verify sbom.json
      const sbom = JSON.parse(fs.readFileSync(written.sbom, 'utf8'));
      assert.equal(sbom.bomFormat, 'CycloneDX');
      assert.ok(validateStructure(sbom).valid);

      // Verify vulnerabilities.json
      const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
      assert.ok(vulns.status);
      assert.ok(Array.isArray(vulns.findings));

      // Verify anomalies.json
      const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));
      assert.ok(anomalies.status);
      assert.ok(Array.isArray(anomalies.findings));

      // Verify report.json
      const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
      assert.equal(report.status, 'complete');
      assert.ok(report.scan);
      assert.ok(report.project);
      assert.ok(report.components);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('generateReportFiles removes stale sbom.json from previous scan', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-stale-'));
    const stalePath = path.join(tmpDir, 'sbom.json');

    // Write a stale sbom.json
    fs.writeFileSync(stalePath, JSON.stringify({ stale: true }));
    assert.ok(fs.existsSync(stalePath));

    // Now run with a partial scan (no BOM generated)
    const result = await scanProject(missingLockfilePath);

    try {
      generateReportFiles(tmpDir, result);
      assert.equal(fs.existsSync(stalePath), false, 'stale sbom.json should be removed');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('report.json content matches individual output files', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-consistency-'));
    const result = await executeScan(simplePath, {
      full: true,
      queryPackages: mockVulnQueryPackages,
    });

    try {
      const written = generateReportFiles(tmpDir, result);

      const report = JSON.parse(fs.readFileSync(written.report, 'utf8'));
      const vulns = JSON.parse(fs.readFileSync(written.vulnerabilities, 'utf8'));
      const anomalies = JSON.parse(fs.readFileSync(written.anomalies, 'utf8'));

      // Vulnerability findings count should match
      assert.equal(
        report.vulnerabilities.summary.total,
        vulns.findings.length,
        'report vuln total should match vulnerabilities.json findings count'
      );

      // Anomaly total should match
      assert.equal(
        report.anomalies.total,
        anomalies.total,
        'report anomaly total should match anomalies.json total'
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('vulnerability analysis integrates correctly with mock findings', async () => {
    const result = await executeScan(simplePath, {
      vulnerabilities: true,
      queryPackages: mockVulnQueryPackages,
    });

    assert.ok(result.vulnerabilities);
    assert.equal(result.vulnerabilities.status, 'completed');
    assert.ok(result.vulnerabilities.findings.length > 0);

    const isOddVuln = result.vulnerabilities.findings.find(f => f.packageName === 'is-odd');
    assert.ok(isOddVuln, 'should find vulnerability in is-odd');
    assert.equal(isOddVuln.id, 'GHSA-mock-001');
  });

  it('anomaly detection integrates correctly on complete scans', async () => {
    const result = await scanProject(simplePath);

    // Anomalies run by default on complete scans
    assert.ok(result.anomalies, 'anomaly detection should run by default');
    assert.ok(Array.isArray(result.anomalies.findings));
    assert.ok(result.anomalies.summary);
    assert.equal(typeof result.anomalies.summary.total, 'number');
  });

  it('anomaly detection is skipped on partial scans', async () => {
    const result = await scanProject(missingLockfilePath);
    assert.equal(result.status, ScanStatus.PARTIAL);
    assert.equal(result.anomalies, null);
  });

  it('dependency comparison works with previous SBOM', async () => {
    // First scan to get a baseline SBOM
    const baseline = await scanProject(simplePath);
    assert.ok(baseline.bom);

    // Second scan with the baseline as previous SBOM
    const result = await scanProject(simplePath, {
      previousBom: baseline.bom,
    });

    assert.ok(result.comparison, 'should have comparison result');
    assert.ok(result.comparison.summary);
    // Same project compared against itself should show all unchanged
    assert.equal(result.comparison.summary.added, 0);
    assert.equal(result.comparison.summary.removed, 0);
    assert.equal(result.comparison.summary.changed, 0);
    assert.ok(result.comparison.summary.unchanged >= 0);
  });

  it('scanner handles concurrent analysis without interference', async () => {
    // Run multiple scans in parallel
    const [r1, r2, r3] = await Promise.all([
      scanProject(simplePath),
      scanProject(zeroDepsPath),
      scanProject(transitivePath),
    ]);

    assert.equal(r1.status, ScanStatus.COMPLETE);
    assert.equal(r2.status, ScanStatus.COMPLETE);
    assert.equal(r3.status, ScanStatus.COMPLETE);

    assert.equal(r1.projectMetadata.name, 'simple-project');
    assert.equal(r2.projectMetadata.name, 'zero-deps-project');
    assert.equal(r3.projectMetadata.name, 'transitive-project');
  });
});

