import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../src/scanner/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');
const simplePath = path.join(fixturesDir, 'simple-project');
const transitivePath = path.join(fixturesDir, 'transitive-project');
const workspaceLockfilePath = path.join(fixturesDir, 'workspace-with-lockfile-project');

describe('Order 16: Anomaly Detection and Dependency Comparison Integration', () => {

  // 1. Normal scanning includes anomaly detection
  it('1. complete scan includes anomalies field with findings and summary', async () => {
    const result = await scanProject(simplePath);

    assert.equal(result.status, 'complete');
    assert.ok(result.anomalies, 'anomalies should be populated for complete scans');
    assert.ok(Array.isArray(result.anomalies.findings));
    assert.ok(result.anomalies.summary);
    assert.equal(typeof result.anomalies.summary.total, 'number');
    assert.equal(typeof result.anomalies.summary.bySeverity.error, 'number');
    assert.equal(typeof result.anomalies.summary.bySeverity.warning, 'number');
    assert.equal(typeof result.anomalies.summary.bySeverity.info, 'number');
  });

  // 2. Anomaly findings have consistent structure
  it('2. each anomaly finding has type, severity, affectedComponent, and explanation', async () => {
    const result = await scanProject(workspaceLockfilePath);
    assert.ok(result.anomalies);
    assert.ok(result.anomalies.findings.length > 0, 'workspace project has anomaly findings');

    for (const f of result.anomalies.findings) {
      assert.ok(f.type, 'anomaly must have type');
      assert.ok(f.severity, 'anomaly must have severity');
      assert.ok(['error', 'warning', 'info'].includes(f.severity));
      assert.ok('affectedComponent' in f, 'anomaly must have affectedComponent field');
      assert.ok(typeof f.explanation === 'string' && f.explanation.length > 0, 'anomaly must have explanation');

      // Each anomaly explanation must explain:
      // - Why the component was flagged
      // - What inconsistency or unusual behavior was detected
      // - Why the finding matters
      assert.ok(f.explanation.includes('was flagged:'), 'explanation should state why flagged');
      assert.ok(f.explanation.includes('Why this matters:'), 'explanation should explain why finding matters');
    }
  });

  // 3. Anomalies are separate from vulnerabilities
  it('3. anomalies are completely separate from vulnerability findings', async () => {
    const resultWithoutVuln = await scanProject(workspaceLockfilePath);
    assert.ok(resultWithoutVuln.anomalies);
    assert.ok(resultWithoutVuln.anomalies.findings.length > 0);
    assert.equal(resultWithoutVuln.vulnerabilities, null, 'vulnerabilities should be null when not requested');

    // With vulnerabilities requested, both exist independently
    const resultWithVuln = await scanProject(workspaceLockfilePath, {
      vulnerabilities: true,
      queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })),
    });
    assert.ok(resultWithVuln.anomalies);
    assert.ok(resultWithVuln.vulnerabilities);
    assert.notEqual(resultWithVuln.anomalies, resultWithVuln.vulnerabilities);
    // Anomalies are not classified as vulnerabilities
    assert.equal(resultWithVuln.vulnerabilities.findings.length, 0);
    assert.ok(resultWithVuln.anomalies.findings.length > 0);
  });

  // 4. A valid SBOM remains valid when anomalies are detected
  it('4. valid SBOM remains valid and is not invalidated by anomalies', async () => {
    const result = await scanProject(workspaceLockfilePath);

    assert.equal(result.status, 'complete');
    assert.ok(result.bom, 'BOM should still be present');
    assert.ok(result.validation?.valid, 'BOM validation should still pass');
    assert.ok(result.anomalies.findings.length > 0, 'anomalies were found');
  });

  // 5. No anomalies or comparison on failed/partial scans
  it('5. failed scan returns null anomalies and null comparison', async () => {
    const result = await scanProject('/nonexistent/path');

    assert.equal(result.status, 'failed');
    assert.equal(result.anomalies, null);
    assert.equal(result.comparison, null);
  });

  // 6. Partial scan returns null anomalies
  it('6. partial scan returns null anomalies', async () => {
    const result = await scanProject(path.join(fixturesDir, 'missing-lockfile-project'));

    assert.equal(result.status, 'partial');
    assert.equal(result.anomalies, null);
    assert.equal(result.bom, null);
  });

  // 7. Normal scan without previous SBOM has null comparison
  it('7. scan without previousBom option returns null comparison', async () => {
    const result = await scanProject(simplePath);

    assert.equal(result.comparison, null);
  });

  // 8. Scan with previous SBOM returns comparison results
  it('8. scan with previousBom option returns comparison results', async () => {
    // First scan to get a BOM to use as previous
    const first = await scanProject(simplePath);
    assert.ok(first.bom);

    // Second scan with previousBom
    const second = await scanProject(simplePath, { previousBom: first.bom });

    assert.ok(second.comparison, 'comparison should be populated');
    assert.equal(second.comparison.status, 'completed');
    assert.ok(second.comparison.summary);
    assert.equal(typeof second.comparison.summary.added, 'number');
    assert.equal(typeof second.comparison.summary.removed, 'number');
    assert.equal(typeof second.comparison.summary.changed, 'number');
    assert.equal(typeof second.comparison.summary.unchanged, 'number');
    assert.ok(Array.isArray(second.comparison.added));
    assert.ok(Array.isArray(second.comparison.removed));
    assert.ok(Array.isArray(second.comparison.changed));
    assert.ok(Array.isArray(second.comparison.unchanged));
  });

  // 9. Same BOM compared to itself shows no changes
  it('9. comparing same BOM shows all components unchanged', async () => {
    const result1 = await scanProject(simplePath);
    const result2 = await scanProject(simplePath, { previousBom: result1.bom });

    assert.ok(result2.comparison);
    assert.equal(result2.comparison.summary.added, 0);
    assert.equal(result2.comparison.summary.removed, 0);
    assert.equal(result2.comparison.summary.changed, 0);
    assert.ok(result2.comparison.summary.unchanged > 0);
  });

  // 10. Detects added components
  it('10. detects added components when current has more dependencies', async () => {
    // simple-project has: is-odd, is-number (2 third-party)
    // transitive-project has: accepts, mime-types, mime-db, negotiator (4 third-party)
    const prev = await scanProject(simplePath);
    const curr = await scanProject(transitivePath, { previousBom: prev.bom });

    assert.ok(curr.comparison);
    // transitive-project components are new (added)
    assert.ok(curr.comparison.added.length > 0, 'should detect added components');
    for (const item of curr.comparison.added) {
      assert.equal(item.changeType, 'added');
      assert.ok(item.explanation);
      assert.ok(item.name);
    }
  });

  // 11. Detects removed components
  it('11. detects removed components when current has fewer dependencies', async () => {
    const prev = await scanProject(transitivePath);
    const curr = await scanProject(simplePath, { previousBom: prev.bom });

    assert.ok(curr.comparison);
    assert.ok(curr.comparison.removed.length > 0, 'should detect removed components');
    for (const item of curr.comparison.removed) {
      assert.equal(item.changeType, 'removed');
      assert.ok(item.explanation);
    }
  });

  // 12. Comparison with modified components (version change)
  it('12. detects modified components when versions differ', async () => {
    // Create a fake previous BOM with a different version
    const curr = await scanProject(simplePath);
    assert.ok(curr.bom);

    const prevBom = JSON.parse(JSON.stringify(curr.bom));
    // Change a component version to simulate upgrade
    if (prevBom.components.length > 0) {
      prevBom.components[0].version = '0.0.1';
    }

    const result = await scanProject(simplePath, { previousBom: prevBom });
    assert.ok(result.comparison);
    // Should detect at least one change (the modified component)
    assert.ok(
      result.comparison.changed.length > 0 || result.comparison.added.length > 0 || result.comparison.removed.length > 0,
      'should detect at least one difference'
    );
  });

  // 13. Existing scanning still works (backward compatibility)
  it('13. existing scanProject without options works unchanged', async () => {
    const result = await scanProject(simplePath);

    assert.equal(result.status, 'complete');
    assert.ok(result.bom);
    assert.ok(result.validation?.valid);
    assert.ok(Array.isArray(result.components));
    assert.ok(result.components.length > 0);
    assert.equal(result.vulnerabilities, null);
    assert.equal(result.comparison, null);
    // anomalies auto-runs on complete scans
    assert.ok(result.anomalies);
  });

  // 14. Comparison entries have explanations
  it('14. comparison change entries include explanations', async () => {
    const prev = await scanProject(simplePath);
    const curr = await scanProject(transitivePath, { previousBom: prev.bom });

    assert.ok(curr.comparison);
    for (const item of [...curr.comparison.added, ...curr.comparison.removed, ...curr.comparison.changed]) {
      assert.ok(typeof item.explanation === 'string' && item.explanation.length > 0,
        `Missing explanation for ${item.name}`);
    }
    for (const item of curr.comparison.unchanged) {
      assert.ok(typeof item.explanation === 'string');
    }
  });

  // 15. Supports previousSbom alias
  it('15. supports previousSbom option alias identically to previousBom', async () => {
    const prev = await scanProject(simplePath);
    const curr = await scanProject(simplePath, { previousSbom: prev.bom });

    assert.ok(curr.comparison);
    assert.equal(curr.comparison.status, 'completed');
    assert.equal(curr.comparison.summary.unchanged > 0, true);
  });

  // 16. Supports previous SBOM as file path string
  it('16. loads previous SBOM directly from filesystem path string', async () => {
    const prev = await scanProject(simplePath);
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-prev-sbom-'));
    const prevFile = path.join(tmpDir, 'previous.cdx.json');
    fs.writeFileSync(prevFile, JSON.stringify(prev.bom), 'utf8');

    try {
      const curr = await scanProject(simplePath, { previousSbom: prevFile });
      assert.ok(curr.comparison);
      assert.equal(curr.comparison.status, 'completed');
      assert.ok(curr.comparison.summary.unchanged > 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 17. Handles nonexistent previous SBOM path gracefully without failing scan
  it('17. handles nonexistent previous SBOM path gracefully without failing scan or invalidating SBOM', async () => {
    const curr = await scanProject(simplePath, { previousSbom: '/does/not/exist/prev-sbom.json' });

    assert.equal(curr.status, 'complete');
    assert.ok(curr.bom);
    assert.ok(curr.validation?.valid);
    assert.equal(curr.comparison, null);
    assert.ok(curr.warnings.some(w => w.message.includes('Previous SBOM file not found')));
  });

  // 18. Handles malformed previous SBOM file gracefully
  it('18. handles malformed previous SBOM file gracefully without failing scan or invalidating SBOM', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-malformed-prev-'));
    const malformedFile = path.join(tmpDir, 'malformed.json');
    fs.writeFileSync(malformedFile, '{ not valid json ...', 'utf8');

    try {
      const curr = await scanProject(simplePath, { previousSbom: malformedFile });
      assert.equal(curr.status, 'complete');
      assert.ok(curr.bom);
      assert.ok(curr.validation?.valid);
      assert.equal(curr.comparison, null);
      assert.ok(curr.warnings.some(w => w.message.includes('Failed to read previous SBOM file')));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 19. Partial scan with previous SBOM does not compare incomplete data
  it('19. partial scan with previous SBOM does not generate comparison on incomplete data', async () => {
    const prev = await scanProject(simplePath);
    const partialCurr = await scanProject(path.join(fixturesDir, 'missing-lockfile-project'), {
      previousBom: prev.bom,
    });

    assert.equal(partialCurr.status, 'partial');
    assert.equal(partialCurr.bom, null);
    assert.equal(partialCurr.comparison, null);
    assert.ok(partialCurr.warnings.some(w => w.message.includes('Dependency comparison skipped')));
  });

  // 20. Explicitly disabling anomaly detection via options.anomalies = false
  it('20. skips anomaly detection when options.anomalies is false', async () => {
    const result = await scanProject(simplePath, { anomalies: false });

    assert.equal(result.status, 'complete');
    assert.ok(result.bom);
    assert.ok(result.validation?.valid);
    assert.equal(result.anomalies, null);
  });
});

