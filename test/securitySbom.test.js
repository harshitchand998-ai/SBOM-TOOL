import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanProject } from '../src/scanner/index.js';
import { executeScan } from '../src/engine/index.js';
import { queryPackage, queryPackages, OsvError } from '../src/osvClient.js';
import {
  matchVulnerabilities,
  evaluateVersionAgainstRange,
  isVersionAffected,
} from '../src/vulnerabilityMatcher.js';
import {
  generateFindings,
  extractSeverity,
  extractFixedVersions,
} from '../src/vulnerabilityFindings.js';
import { checkVulnerabilities } from '../src/vulnerabilityChecker.js';
import { computeSeverityCounts } from '../src/reportGenerator.js';
import { validateStructure, validatePurl } from '../src/validator.js';
import { ScanStatus } from '../src/errors.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');
const simplePath = path.join(fixturesDir, 'simple-project');
const largePath = path.join(fixturesDir, 'large-project');
const monorepoPath = path.join(fixturesDir, 'monorepo-project');

// --- Documented Known Vulnerability Fixtures ---
const lodashPrototypePollution = {
  id: 'GHSA-p6mc-m468-83gw',
  aliases: ['CVE-2020-8203'],
  summary: 'Prototype Pollution in lodash',
  details: 'Versions of lodash before 4.17.21 are vulnerable to prototype pollution.',
  severity: [{ type: 'CVSS_V3', score: '7.4' }],
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203' }],
};

const lodashRedos = {
  id: 'GHSA-4858-n2wf-5j4w',
  aliases: ['CVE-2021-23337'],
  summary: 'Command Injection and ReDoS in lodash',
  severity: [{ type: 'CVSS_V3', score: '5.3' }],
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' }],
};

const minimistPrototypePollution = {
  id: 'GHSA-vh95-rmgr-6w49',
  aliases: ['CVE-2020-7598'],
  summary: 'Prototype Pollution in minimist',
  severity: [{ type: 'CVSS_V3', score: '9.8' }],
  affected: [
    {
      package: { name: 'minimist', ecosystem: 'npm' },
      ranges: [
        { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.1' }] },
        { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }] },
      ],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-7598' }],
};

const qsPrototypePollution = {
  id: 'GHSA-hrpp-h998-j3pp',
  aliases: ['CVE-2017-1000048'],
  summary: 'Prototype Pollution in qs',
  severity: [{ type: 'CVSS_V3', score: '7.5' }],
  affected: [
    {
      package: { name: 'qs', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '6.5.0' }, { fixed: '6.5.2' }] }],
    },
  ],
  references: [{ type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2017-1000048' }],
};

describe('Order 21: Security and CycloneDX 1.7 SBOM Testing', () => {

  // =========================================================================
  // A. Vulnerability Detection Testing
  // =========================================================================
  describe('A. Vulnerability Detection Testing', () => {
    it('correctly identifies vulnerable npm packages with documented advisories', () => {
      const deps = [
        { name: 'lodash', version: '4.17.15', dependencyType: 'direct', ecosystem: 'npm' },
        { name: 'minimist', version: '0.2.0', dependencyType: 'transitive', ecosystem: 'npm' },
        { name: 'qs', version: '6.5.1', dependencyType: 'direct', ecosystem: 'npm' },
      ];
      const advisories = [lodashPrototypePollution, minimistPrototypePollution, qsPrototypePollution];

      const findings = generateFindings(deps, advisories);
      assert.equal(findings.length, 3, 'Must detect all 3 known vulnerable dependencies');

      const byPkg = Object.fromEntries(findings.map(f => [f.packageName, f]));
      assert.equal(byPkg.lodash.id, 'GHSA-p6mc-m468-83gw');
      assert.equal(byPkg.lodash.status, 'vulnerable');
      assert.deepEqual(byPkg.lodash.fixedVersions, ['4.17.21']);

      assert.equal(byPkg.minimist.id, 'GHSA-vh95-rmgr-6w49');
      assert.equal(byPkg.minimist.status, 'vulnerable');
      assert.deepEqual(byPkg.minimist.fixedVersions, ['0.2.1']);
      // Complete advisory has fixes across branches:
      assert.deepEqual(extractFixedVersions(minimistPrototypePollution.affected[0]), ['0.2.1', '1.2.3']);

      assert.equal(byPkg.qs.id, 'GHSA-hrpp-h998-j3pp');
      assert.equal(byPkg.qs.status, 'vulnerable');
    });

    it('does not produce false-positive findings for non-vulnerable (patched) versions', () => {
      const patchedDeps = [
        { name: 'lodash', version: '4.17.21', dependencyType: 'direct', ecosystem: 'npm' },
        { name: 'minimist', version: '1.2.6', dependencyType: 'transitive', ecosystem: 'npm' },
        { name: 'qs', version: '6.5.3', dependencyType: 'direct', ecosystem: 'npm' },
      ];
      const advisories = [lodashPrototypePollution, minimistPrototypePollution, qsPrototypePollution];

      const findings = generateFindings(patchedDeps, advisories);
      assert.equal(findings.length, 0, 'Patched versions must produce 0 false-positive findings');
    });

    it('identifies multiple vulnerabilities affecting a single package', () => {
      const deps = [{ name: 'lodash', version: '4.17.11', dependencyType: 'direct', ecosystem: 'npm' }];
      const advisories = [lodashPrototypePollution, lodashRedos];

      const findings = generateFindings(deps, advisories);
      assert.equal(findings.length, 2, 'Package with 2 advisories must produce 2 distinct findings');
      const ids = findings.map(f => f.id).sort();
      assert.deepEqual(ids, ['GHSA-4858-n2wf-5j4w', 'GHSA-p6mc-m468-83gw']);
    });

    it('detects vulnerabilities during full scan workflow without altering SBOM validity', async () => {
      const scanResult = await executeScan(simplePath, {
        vulnerabilities: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({
          package: p,
          vulnerabilities: p.name === 'is-odd' ? [{
            id: 'GHSA-odd-01',
            summary: 'Vulnerability in is-odd',
            severity: [{ type: 'CVSS_V3', score: '8.0' }],
            affected: [{
              package: { name: 'is-odd', ecosystem: 'npm' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.0.0' }] }],
            }],
          }] : [],
        })),
      });

      assert.equal(scanResult.status, ScanStatus.COMPLETE);
      assert.ok(scanResult.bom);
      assert.equal(scanResult.validation?.valid, true);
      assert.equal(scanResult.vulnerabilities.vulnerablePackages, 1);
      assert.equal(scanResult.vulnerabilities.findings[0].id, 'GHSA-odd-01');
    });
  });

  // =========================================================================
  // B. OSV API Testing
  // =========================================================================
  describe('B. OSV API Testing & Error Handling', () => {
    let originalFetch;

    beforeEach(() => {
      originalFetch = globalThis.fetch;
    });

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    it('verifies structure and correctness of successful OSV API responses', async () => {
      globalThis.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          vulns: [{ id: 'GHSA-test-1', summary: 'Test vuln' }],
        }),
      });

      const mockResult = await queryPackage({ name: 'lodash', version: '4.17.15', ecosystem: 'npm' });
      assert.ok(mockResult.package);
      assert.equal(mockResult.package.name, 'lodash');
      assert.equal(mockResult.package.version, '4.17.15');
      assert.equal(mockResult.package.ecosystem, 'npm');
      assert.equal(mockResult.vulnerabilities.length, 1);
      assert.equal(mockResult.vulnerabilities[0].id, 'GHSA-test-1');
    });

    it('throws expected OsvErrors for network failure, timeout, HTTP 429, HTTP 500, and bad JSON', async () => {
      // 1. Network failure
      globalThis.fetch = async () => { throw new Error('Connection refused'); };
      await assert.rejects(
        () => queryPackage({ name: 'lodash', version: '1.0.0' }),
        { name: 'OsvError', code: 'NETWORK_ERROR' }
      );

      // 2. Timeout
      const timeoutErr = new Error('The operation was aborted due to timeout');
      timeoutErr.name = 'TimeoutError';
      globalThis.fetch = async () => { throw timeoutErr; };
      await assert.rejects(
        () => queryPackage({ name: 'lodash', version: '1.0.0' }),
        { name: 'OsvError', code: 'REQUEST_TIMEOUT' }
      );

      // 3. HTTP 429 Rate limited
      globalThis.fetch = async () => ({ ok: false, status: 429 });
      await assert.rejects(
        () => queryPackage({ name: 'lodash', version: '1.0.0' }),
        { name: 'OsvError', code: 'RATE_LIMITED' }
      );

      // 4. HTTP 500 Server error
      globalThis.fetch = async () => ({ ok: false, status: 500 });
      await assert.rejects(
        () => queryPackage({ name: 'lodash', version: '1.0.0' }),
        { name: 'OsvError', code: 'API_ERROR' }
      );

      // 5. Invalid JSON
      globalThis.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => { throw new SyntaxError('Unexpected token'); },
      });
      await assert.rejects(
        () => queryPackage({ name: 'lodash', version: '1.0.0' }),
        { name: 'OsvError', code: 'INVALID_RESPONSE' }
      );
    });

    it('returns empty vulnerabilities array for packages with no known vulnerabilities', async () => {
      globalThis.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ vulns: [] }),
      });
      const single = await queryPackage({ name: 'safe-pkg', version: '1.0.0' });
      assert.deepEqual(single.vulnerabilities, []);

      const result = await checkVulnerabilities(
        [{ name: 'safe-pkg', version: '1.0.0', dependencyType: 'direct', ecosystem: 'npm' }],
        { queryPackages: async (pkgs) => pkgs.map(p => ({ package: p, vulnerabilities: [] })) }
      );
      assert.equal(result.status, 'completed');
      assert.equal(result.vulnerablePackages, 0);
      assert.equal(result.findings.length, 0);
      assert.equal(result.errors.length, 0);
    });

    it('rejects invalid package query inputs before calling the network', async () => {
      await assert.rejects(() => queryPackage(null), { code: 'INVALID_INPUT' });
      await assert.rejects(() => queryPackage({ name: '', version: '1.0.0' }), { code: 'INVALID_INPUT' });
      await assert.rejects(() => queryPackage({ name: 'lodash', version: '' }), { code: 'INVALID_INPUT' });
      await assert.rejects(() => queryPackage({ name: 'lodash', version: '1.0.0', ecosystem: '' }), { code: 'INVALID_INPUT' });
    });

    it('handles batch package queries with partial network failures gracefully', async () => {
      const pkgs = [
        { name: 'pkg-a', version: '1.0.0' },
        { name: 'pkg-b', version: '2.0.0' },
      ];
      // simulate batch where pkg-b fails with network error
      const mockQueryPackages = async (packages) => packages.map(p => (
        p.name === 'pkg-b'
          ? { package: p, vulnerabilities: [], error: { code: 'NETWORK_ERROR', message: 'Connection refused' } }
          : { package: p, vulnerabilities: [] }
      ));

      const res = await checkVulnerabilities(
        pkgs.map(p => ({ ...p, dependencyType: 'direct', ecosystem: 'npm' })),
        { queryPackages: mockQueryPackages }
      );

      assert.equal(res.status, 'partial');
      assert.equal(res.errors.length, 1);
      assert.equal(res.errors[0].package.name, 'pkg-b');
      assert.equal(res.errors[0].code, 'NETWORK_ERROR');
    });

    it('isolates total API failure without failing the overall SBOM workflow', async () => {
      const scanResult = await executeScan(simplePath, {
        vulnerabilities: true,
        queryPackages: async (pkgs) => pkgs.map(p => ({
          package: p,
          vulnerabilities: [],
          error: { code: 'NETWORK_ERROR', message: 'OSV API is unreachable' },
        })),
      });

      // Core SBOM remains intact and valid despite vulnerability query failure
      assert.equal(scanResult.status, ScanStatus.COMPLETE);
      assert.ok(scanResult.bom);
      assert.equal(scanResult.validation?.valid, true);
      assert.equal(scanResult.vulnerabilities.status, 'failed');
      assert.ok(scanResult.vulnerabilities.errors.length > 0);
    });
  });

  // =========================================================================
  // C. Vulnerability Matching
  // =========================================================================
  describe('C. Vulnerability Matching & Range Evaluation', () => {
    it('matches versions inside SEMVER introduced/fixed bounds', () => {
      const range = {
        type: 'SEMVER',
        events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }],
      };
      assert.equal(evaluateVersionAgainstRange('1.0.0', range).isAffected, true);
      assert.equal(evaluateVersionAgainstRange('1.1.0', range).isAffected, true);
      assert.equal(evaluateVersionAgainstRange('1.2.2', range).isAffected, true);
    });

    it('ensures versions outside affected ranges are not marked vulnerable', () => {
      const range = {
        type: 'SEMVER',
        events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }],
      };
      // Before introduced
      assert.equal(evaluateVersionAgainstRange('0.9.9', range).isAffected, false);
      // Equal to or greater than fixed
      assert.equal(evaluateVersionAgainstRange('1.2.3', range).isAffected, false);
      assert.equal(evaluateVersionAgainstRange('2.0.0', range).isAffected, false);
    });

    it('correctly identifies and extracts fixed versions from range events', () => {
      const fixedVersions = extractFixedVersions(minimistPrototypePollution.affected[0]);
      assert.deepEqual(fixedVersions, ['0.2.1', '1.2.3']);
    });

    it('excludes non-semver git commit hashes from extracted fixed versions', () => {
      const affected = {
        package: { name: 'sample', ecosystem: 'npm' },
        ranges: [
          {
            type: 'SEMVER',
            events: [{ introduced: '0' }, { fixed: '1.4.0' }],
          },
          {
            type: 'GIT',
            events: [{ introduced: '0' }, { fixed: 'a1b2c3d4e5f678901234567890abcdef12345678' }],
          },
        ],
      };
      const fixed = extractFixedVersions(affected);
      assert.deepEqual(fixed, ['1.4.0'], 'Must exclude git commit SHA fixes');
    });

    it('handles edge cases of missing or non-semver version information safely', () => {
      // Non-semver installed version
      const nonSemverResult = isVersionAffected('git+https://github.com/foo/bar.git#master', minimistPrototypePollution.affected[0]);
      assert.equal(nonSemverResult.isAffected, false);
      assert.equal(nonSemverResult.status, 'UNABLE_TO_EVALUATE');

      // Empty ranges
      const noRangesResult = isVersionAffected('1.0.0', { package: { name: 'foo', ecosystem: 'npm' }, ranges: [] });
      assert.equal(noRangesResult.isAffected, false);
      assert.equal(noRangesResult.status, 'UNABLE_TO_EVALUATE');
    });

    it('prevents cross-ecosystem package matching', () => {
      const pypiAdvisory = {
        id: 'PYSEC-2021-1',
        affected: [{ package: { name: 'requests', ecosystem: 'PyPI' }, ranges: [] }],
      };
      const npmDep = { name: 'requests', version: '2.25.1', dependencyType: 'direct', ecosystem: 'npm' };
      const matches = matchVulnerabilities([npmDep], [pypiAdvisory]);
      assert.equal(matches.length, 0, 'npm dependency must not match PyPI advisory');
    });
  });

  // =========================================================================
  // D. Severity Classification
  // =========================================================================
  describe('D. Severity Classification & Finding Fields', () => {
    it('accurately classifies CVSS scores into critical, high, medium, low, unknown', () => {
      const findings = [
        { severity: { score: '9.8' } },
        { severity: { score: '7.5' } },
        { severity: { score: '5.3' } },
        { severity: { score: '2.5' } },
        { severity: null },
      ];
      const counts = computeSeverityCounts(findings);
      assert.equal(counts.critical, 1);
      assert.equal(counts.high, 1);
      assert.equal(counts.medium, 1);
      assert.equal(counts.low, 1);
      assert.equal(counts.unknown, 1);
    });

    it('accurately classifies textual severity ratings', () => {
      const findings = [
        { severity: { score: 'CRITICAL' } },
        { severity: { score: 'HIGH' } },
        { severity: { score: 'MODERATE' } },
        { severity: { score: 'LOW' } },
      ];
      const counts = computeSeverityCounts(findings);
      assert.equal(counts.critical, 1);
      assert.equal(counts.high, 1);
      assert.equal(counts.medium, 1);
      assert.equal(counts.low, 1);
      assert.equal(counts.unknown, 0);
    });

    it('does not invent missing severity or fixed versions when omitted from OSV', () => {
      const minimalVuln = {
        id: 'GHSA-minimal-1',
        affected: [{ package: { name: 'bar', ecosystem: 'npm' } }],
      };
      const dep = { name: 'bar', version: '1.0.0', dependencyType: 'direct', ecosystem: 'npm' };

      const findings = generateFindings([dep], [minimalVuln], { includeUnableToEvaluate: true });
      assert.equal(findings.length, 1);
      assert.equal(findings[0].severity, null, 'Must not invent severity when omitted');
      assert.deepEqual(findings[0].fixedVersions, [], 'Must not invent fixed version when omitted');
    });

    it('verifies vulnerability finding schema contains all expected properties', () => {
      const findings = generateFindings(
        [{ name: 'lodash', version: '4.17.15', dependencyType: 'direct', ecosystem: 'npm' }],
        [lodashPrototypePollution]
      );
      assert.equal(findings.length, 1);
      const f = findings[0];

      assert.equal(f.id, 'GHSA-p6mc-m468-83gw');
      assert.deepEqual(f.aliases, ['CVE-2020-8203']);
      assert.equal(f.packageName, 'lodash');
      assert.equal(f.installedVersion, '4.17.15');
      assert.equal(f.ecosystem, 'npm');
      assert.equal(f.dependencyType, 'direct');
      assert.equal(f.status, 'vulnerable');
      assert.ok(f.severity);
      assert.equal(f.severity.type, 'CVSS_V3');
      assert.equal(f.severity.score, '7.4');
      assert.equal(f.summary, 'Prototype Pollution in lodash');
      assert.ok(f.details);
      assert.ok(Array.isArray(f.affectedRanges));
      assert.deepEqual(f.fixedVersions, ['4.17.21']);
      assert.ok(Array.isArray(f.references));
      assert.equal(f.references[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203');
    });
  });

  // =========================================================================
  // E. CycloneDX 1.7 SBOM Validation
  // =========================================================================
  describe('E. CycloneDX 1.7 SBOM Validation', () => {
    it('validates generated SBOM for simple-project against CycloneDX 1.7 requirements', async () => {
      const res = await scanProject(simplePath);
      assert.equal(res.status, ScanStatus.COMPLETE);
      const bom = res.bom;

      // Top-level structure
      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.specVersion, '1.7');
      assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      assert.equal(bom.version, 1);

      // Metadata
      assert.ok(bom.metadata);
      assert.ok(bom.metadata.timestamp);
      assert.ok(!Number.isNaN(Date.parse(bom.metadata.timestamp)));
      assert.ok(bom.metadata.component);
      assert.equal(bom.metadata.component.type, 'application');
      assert.equal(bom.metadata.component.name, 'simple-project');
      assert.equal(bom.metadata.component.version, '1.0.0');

      // Components
      assert.ok(Array.isArray(bom.components));
      assert.equal(bom.components.length, 2);
      for (const comp of bom.components) {
        assert.equal(comp.type, 'library');
        assert.ok(comp.name);
        assert.ok(comp.version);
        assert.ok(comp['bom-ref']);
        assert.ok(comp.purl);
        assert.equal(validatePurl(comp.purl).valid, true);
        if (comp.hashes) {
          for (const hash of comp.hashes) {
            assert.ok(hash.alg);
            assert.ok(hash.content);
          }
        }
      }

      // Dependencies & Referential Integrity
      assert.ok(Array.isArray(bom.dependencies));
      const rootDep = bom.dependencies.find(d => d.ref === bom.metadata.component['bom-ref']);
      assert.ok(rootDep, 'Root component must have dependency entry');

      // Structural validation
      const validation = validateStructure(bom);
      assert.equal(validation.valid, true);
      assert.equal(validation.errors.length, 0);
    });

    it('validates generated SBOM for large-project with deep transitive dependencies', async () => {
      const res = await scanProject(largePath);
      assert.equal(res.status, ScanStatus.COMPLETE);
      assert.equal(res.bom.specVersion, '1.7');

      const validation = validateStructure(res.bom);
      assert.equal(validation.valid, true);
      assert.equal(validation.errors.length, 0);
    });

    it('validates generated SBOM for monorepo-project with workspaces', async () => {
      const res = await scanProject(monorepoPath);
      assert.equal(res.status, ScanStatus.COMPLETE);
      assert.equal(res.bom.specVersion, '1.7');

      const validation = validateStructure(res.bom);
      assert.equal(validation.valid, true);
      assert.equal(validation.errors.length, 0);
    });
  });

  // =========================================================================
  // F. Invalid and Incomplete SBOM Testing
  // =========================================================================
  describe('F. Invalid and Incomplete SBOM Testing', () => {
    function createValidMinimalBom() {
      const rootRef = 'pkg:npm/app@1.0.0';
      const libRef = 'pkg:npm/dep@2.0.0';
      return {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
        version: 1,
        metadata: {
          timestamp: '2026-11-14T10:00:00.000Z',
          component: {
            type: 'application',
            name: 'app',
            version: '1.0.0',
            'bom-ref': rootRef,
          },
        },
        components: [
          {
            type: 'library',
            name: 'dep',
            version: '2.0.0',
            'bom-ref': libRef,
            purl: libRef,
          },
        ],
        dependencies: [
          { ref: rootRef, dependsOn: [libRef] },
          { ref: libRef, dependsOn: [] },
        ],
      };
    }

    it('rejects BOM with missing or invalid top-level fields', () => {
      assert.equal(validateStructure(null).valid, false);
      assert.equal(validateStructure({}).valid, false);

      const missingFormat = createValidMinimalBom();
      delete missingFormat.bomFormat;
      assert.equal(validateStructure(missingFormat).valid, false);

      const invalidSpec = createValidMinimalBom();
      invalidSpec.specVersion = '2.9';
      assert.equal(validateStructure(invalidSpec).valid, false);

      const badSerial = createValidMinimalBom();
      badSerial.serialNumber = 'not-a-uuid';
      assert.equal(validateStructure(badSerial).valid, false);

      const badVersion = createValidMinimalBom();
      badVersion.version = 0;
      assert.equal(validateStructure(badVersion).valid, false);
    });

    it('rejects BOM with invalid metadata or root component', () => {
      const missingMeta = createValidMinimalBom();
      delete missingMeta.metadata;
      assert.equal(validateStructure(missingMeta).valid, false);

      const badTimestamp = createValidMinimalBom();
      badTimestamp.metadata.timestamp = 'invalid-date';
      assert.equal(validateStructure(badTimestamp).valid, false);

      const missingRoot = createValidMinimalBom();
      delete missingRoot.metadata.component;
      assert.equal(validateStructure(missingRoot).valid, false);
    });

    it('rejects components with missing names, versions, or bom-refs', () => {
      const noName = createValidMinimalBom();
      delete noName.components[0].name;
      assert.equal(validateStructure(noName).valid, false);

      const noVersion = createValidMinimalBom();
      delete noVersion.components[0].version;
      assert.equal(validateStructure(noVersion).valid, false);

      const noRef = createValidMinimalBom();
      delete noRef.components[0]['bom-ref'];
      assert.equal(validateStructure(noRef).valid, false);

      const dupRef = createValidMinimalBom();
      dupRef.components.push({
        type: 'library',
        name: 'dep-dup',
        version: '1.0.0',
        'bom-ref': 'pkg:npm/dep@2.0.0', // duplicate of existing
      });
      assert.equal(validateStructure(dupRef).valid, false);
    });

    it('rejects invalid or malformed PURLs', () => {
      assert.equal(validatePurl('').valid, false);
      assert.equal(validatePurl('http://example.com').valid, false);
      assert.equal(validatePurl('pkg:').valid, false);
      assert.equal(validatePurl('pkg:npm/').valid, false);
      assert.equal(validatePurl('pkg:npm/lodash@').valid, false);
    });

    it('rejects malformed hashes on components', () => {
      const badHashes = createValidMinimalBom();
      badHashes.components[0].hashes = 'not-an-array';
      assert.equal(validateStructure(badHashes).valid, false);

      const missingHashContent = createValidMinimalBom();
      missingHashContent.components[0].hashes = [{ alg: 'SHA-512', content: '' }];
      assert.equal(validateStructure(missingHashContent).valid, false);
    });

    it('rejects broken or dangling dependency references', () => {
      const dangling = createValidMinimalBom();
      dangling.dependencies[0].dependsOn.push('pkg:npm/nonexistent@1.0.0');
      const res = validateStructure(dangling);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('Dangling dependency reference')));

      const missingRootDep = createValidMinimalBom();
      missingRootDep.dependencies = [
        { ref: 'pkg:npm/dep@2.0.0', dependsOn: [] },
      ];
      assert.equal(validateStructure(missingRootDep).valid, false);
    });

    it('ensures rejection of invalid SBOM does not affect valid SBOM generation', async () => {
      // 1. Validate invalid BOM
      const invalid = { bomFormat: 'CycloneDX', specVersion: '1.0' };
      assert.equal(validateStructure(invalid).valid, false);

      // 2. Normal scan succeeds and produces completely valid SBOM
      const validScan = await scanProject(simplePath);
      assert.equal(validScan.status, ScanStatus.COMPLETE);
      assert.equal(validateStructure(validScan.bom).valid, true);
    });
  });
});

