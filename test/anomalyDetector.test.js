/**
 * Tests for Anomaly Detection Module
 * Verifies component metadata checks, dependency relationship validation,
 * deduplication, immutability, and deterministic reporting.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  detectAnomalies,
  summarizeAnomalies,
  parsePurl,
  AnomalyType,
  AnomalySeverity,
} from '../src/anomalyDetector.js';

describe('Anomaly Detector', () => {

  describe('PURL Parsing (parsePurl)', () => {
    it('parses standard npm PURL', () => {
      const parsed = parsePurl('pkg:npm/lodash@4.17.21');
      assert.ok(parsed);
      assert.equal(parsed.type, 'npm');
      assert.equal(parsed.name, 'lodash');
      assert.equal(parsed.fullName, 'lodash');
      assert.equal(parsed.version, '4.17.21');
    });

    it('parses scoped npm PURL with URL-encoded namespace', () => {
      const parsed = parsePurl('pkg:npm/%40babel/core@7.20.0');
      assert.ok(parsed);
      assert.equal(parsed.type, 'npm');
      assert.equal(parsed.namespace, '@babel');
      assert.equal(parsed.name, 'core');
      assert.equal(parsed.fullName, '@babel/core');
      assert.equal(parsed.version, '7.20.0');
    });

    it('returns null for invalid PURL', () => {
      assert.equal(parsePurl('not-a-purl'), null);
      assert.equal(parsePurl(''), null);
      assert.equal(parsePurl(null), null);
      assert.equal(parsePurl(undefined), null);
      assert.equal(parsePurl('pkg:/missing-type'), null);
    });
  });

  describe('Component Metadata Checks', () => {
    it('detects MISSING_NAME when component name is missing, null, empty, or whitespace', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/missing-name@1.0.0',
            purl: 'pkg:npm/missing-name@1.0.0',
          },
          {
            type: 'library',
            name: '',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/empty-name@1.0.0',
            purl: 'pkg:npm/empty-name@1.0.0',
          },
          {
            type: 'library',
            name: '   ',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/space-name@1.0.0',
            purl: 'pkg:npm/space-name@1.0.0',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const missingNameAnomalies = anomalies.filter(a => a.type === AnomalyType.MISSING_NAME);

      assert.equal(missingNameAnomalies.length, 3);
      for (const a of missingNameAnomalies) {
        assert.equal(a.severity, AnomalySeverity.ERROR);
        assert.equal(a.field, 'name');
        assert.ok(a.message.includes('missing a package name'));
      }
    });

    it('detects MISSING_VERSION when version is omitted, empty, or null', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'pkg-no-version',
            'bom-ref': 'pkg:npm/pkg-no-version',
            purl: 'pkg:npm/pkg-no-version',
          },
          {
            type: 'library',
            name: 'pkg-empty-version',
            version: '   ',
            'bom-ref': 'pkg:npm/pkg-empty-version',
            purl: 'pkg:npm/pkg-empty-version',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const missingVerAnomalies = anomalies.filter(a => a.type === AnomalyType.MISSING_VERSION);

      assert.equal(missingVerAnomalies.length, 2);
      for (const a of missingVerAnomalies) {
        assert.equal(a.severity, AnomalySeverity.WARNING);
        assert.equal(a.field, 'version');
      }
    });

    it('detects INVALID_VERSION when version fails SemVer 2.0.0 validation', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'invalid-semver-pkg',
            version: '1.0.0.0',
            'bom-ref': 'pkg:npm/invalid-semver-pkg@1.0.0.0',
            purl: 'pkg:npm/invalid-semver-pkg@1.0.0.0',
          },
          {
            type: 'library',
            name: 'leading-zero-pkg',
            version: '01.2.3',
            'bom-ref': 'pkg:npm/leading-zero-pkg@01.2.3',
            purl: 'pkg:npm/leading-zero-pkg@01.2.3',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const invalidVerAnomalies = anomalies.filter(a => a.type === AnomalyType.INVALID_VERSION);

      assert.equal(invalidVerAnomalies.length, 2);
      for (const a of invalidVerAnomalies) {
        assert.equal(a.severity, AnomalySeverity.ERROR);
        assert.equal(a.field, 'version');
        assert.ok(a.details.includes('SemVer 2.0.0'));
      }
    });

    it('accepts valid SemVer versions without reporting INVALID_VERSION', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'valid-pkg-1',
            version: '1.2.3',
            'bom-ref': 'pkg:npm/valid-pkg-1@1.2.3',
            purl: 'pkg:npm/valid-pkg-1@1.2.3',
            externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/valid-pkg-1' }],
          },
          {
            type: 'library',
            name: 'valid-pkg-2',
            version: '2.0.0-beta.1+build.123',
            'bom-ref': 'pkg:npm/valid-pkg-2@2.0.0-beta.1+build.123',
            purl: 'pkg:npm/valid-pkg-2@2.0.0-beta.1+build.123',
            externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/valid-pkg-2' }],
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const verAnomalies = anomalies.filter(a => a.type === AnomalyType.INVALID_VERSION || a.type === AnomalyType.MISSING_VERSION);
      assert.equal(verAnomalies.length, 0);
    });

    it('detects MISSING_PURL when purl attribute is absent', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'no-purl-pkg',
            version: '1.0.0',
            'bom-ref': 'no-purl-ref',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const missingPurl = anomalies.filter(a => a.type === AnomalyType.MISSING_PURL);

      assert.equal(missingPurl.length, 1);
      assert.equal(missingPurl[0].severity, AnomalySeverity.WARNING);
      assert.equal(missingPurl[0].field, 'purl');
    });

    it('detects INVALID_PURL when purl is syntactically malformed', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'bad-purl-pkg',
            version: '1.0.0',
            'bom-ref': 'bad-purl-ref',
            purl: 'invalid:not-a-purl',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const invalidPurl = anomalies.filter(a => a.type === AnomalyType.INVALID_PURL);

      assert.equal(invalidPurl.length, 1);
      assert.equal(invalidPurl[0].severity, AnomalySeverity.ERROR);
    });

    it('detects INCONSISTENT_PURL when PURL name, version, or ecosystem differs from component metadata', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'lodash',
            version: '4.17.21',
            'bom-ref': 'pkg:npm/express@4.17.21',
            purl: 'pkg:npm/express@4.17.21', // name mismatch
          },
          {
            type: 'library',
            name: 'accepts',
            version: '1.3.8',
            'bom-ref': 'pkg:npm/accepts@1.3.7',
            purl: 'pkg:npm/accepts@1.3.7', // version mismatch
          },
          {
            type: 'library',
            name: 'requests',
            version: '2.28.0',
            ecosystem: 'npm',
            'bom-ref': 'pkg:pypi/requests@2.28.0',
            purl: 'pkg:pypi/requests@2.28.0', // ecosystem mismatch
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const inconsistentPurl = anomalies.filter(a => a.type === AnomalyType.INCONSISTENT_PURL);

      assert.equal(inconsistentPurl.length, 3);
      for (const a of inconsistentPurl) {
        assert.equal(a.severity, AnomalySeverity.ERROR);
      }

      assert.ok(inconsistentPurl.some(a => a.field === 'purl.name'));
      assert.ok(inconsistentPurl.some(a => a.field === 'purl.version'));
      assert.ok(inconsistentPurl.some(a => a.field === 'purl.type'));
    });

    it('detects MISSING_REFERENCES on library components lacking externalReferences', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            type: 'library',
            name: 'lodash',
            version: '4.17.21',
            'bom-ref': 'pkg:npm/lodash@4.17.21',
            purl: 'pkg:npm/lodash@4.17.21',
            // no externalReferences
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const missingRefs = anomalies.filter(a => a.type === AnomalyType.MISSING_REFERENCES);

      assert.equal(missingRefs.length, 1);
      assert.equal(missingRefs[0].severity, AnomalySeverity.INFO);
      assert.equal(missingRefs[0].field, 'externalReferences');
    });

    it('produces no metadata anomalies for complete, valid components', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: {
          component: {
            type: 'application',
            name: 'my-app',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/my-app@1.0.0',
            purl: 'pkg:npm/my-app@1.0.0',
          },
        },
        components: [
          {
            type: 'library',
            name: '@scope/package-a',
            version: '1.2.3',
            'bom-ref': 'pkg:npm/%40scope/package-a@1.2.3',
            purl: 'pkg:npm/%40scope/package-a@1.2.3',
            externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/@scope/package-a' }],
          },
        ],
        dependencies: [
          {
            ref: 'pkg:npm/my-app@1.0.0',
            dependsOn: ['pkg:npm/%40scope/package-a@1.2.3'],
          },
          {
            ref: 'pkg:npm/%40scope/package-a@1.2.3',
            dependsOn: [],
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      assert.equal(anomalies.length, 0);
    });
  });

  describe('Dependency Relationship Checks', () => {
    it('detects UNRESOLVED_DEPENDENCY when a reference does not exist in components', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: {
          component: {
            name: 'app',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/app@1.0.0',
            purl: 'pkg:npm/app@1.0.0',
          },
        },
        components: [
          {
            name: 'pkg-a',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/pkg-a@1.0.0',
            purl: 'pkg:npm/pkg-a@1.0.0',
          },
        ],
        dependencies: [
          {
            ref: 'pkg:npm/app@1.0.0',
            dependsOn: ['pkg:npm/ghost-dependency@2.0.0'],
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const unresolved = anomalies.filter(a => a.type === AnomalyType.UNRESOLVED_DEPENDENCY);

      assert.equal(unresolved.length, 1);
      assert.equal(unresolved[0].severity, AnomalySeverity.ERROR);
      assert.equal(unresolved[0].dependencyRef, 'pkg:npm/ghost-dependency@2.0.0');
      assert.equal(unresolved[0].parentRef, 'pkg:npm/app@1.0.0');
    });

    it('detects DUPLICATE_BOM_REF when multiple components declare identical bom-ref', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            name: 'pkg-one',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/shared-ref@1.0.0',
            purl: 'pkg:npm/pkg-one@1.0.0',
          },
          {
            name: 'pkg-two',
            version: '1.0.0',
            'bom-ref': 'pkg:npm/shared-ref@1.0.0', // duplicate bom-ref
            purl: 'pkg:npm/pkg-two@1.0.0',
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const duplicateRefs = anomalies.filter(a => a.type === AnomalyType.DUPLICATE_BOM_REF);

      assert.equal(duplicateRefs.length, 1);
      assert.equal(duplicateRefs[0].severity, AnomalySeverity.ERROR);
      assert.ok(duplicateRefs[0].message.includes('Duplicate component bom-ref'));
    });

    it('detects DUPLICATE_DEPENDENCY_EDGE for duplicate parent entries or duplicate child references', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: {
          component: { name: 'app', version: '1.0.0', 'bom-ref': 'ref-app', purl: 'pkg:npm/app@1.0.0' },
        },
        components: [
          { name: 'pkg-a', version: '1.0.0', 'bom-ref': 'ref-a', purl: 'pkg:npm/pkg-a@1.0.0' },
        ],
        dependencies: [
          {
            ref: 'ref-app',
            dependsOn: ['ref-a', 'ref-a'], // duplicate child
          },
          {
            ref: 'ref-app', // duplicate parent entry
            dependsOn: ['ref-a'],
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const duplicateEdges = anomalies.filter(a => a.type === AnomalyType.DUPLICATE_DEPENDENCY_EDGE);

      assert.ok(duplicateEdges.length >= 2);
      for (const a of duplicateEdges) {
        assert.equal(a.severity, AnomalySeverity.WARNING);
      }
    });

    it('detects SELF_REFERENCING_DEPENDENCY when a component depends on itself', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          {
            name: 'circular-pkg',
            version: '1.0.0',
            'bom-ref': 'ref-circular',
            purl: 'pkg:npm/circular-pkg@1.0.0',
          },
        ],
        dependencies: [
          {
            ref: 'ref-circular',
            dependsOn: ['ref-circular'],
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const selfRef = anomalies.filter(a => a.type === AnomalyType.SELF_REFERENCING_DEPENDENCY);

      assert.equal(selfRef.length, 1);
      assert.equal(selfRef[0].severity, AnomalySeverity.ERROR);
      assert.equal(selfRef[0].parentRef, 'ref-circular');
      assert.equal(selfRef[0].dependencyRef, 'ref-circular');
    });

    it('detects INVALID_DEPENDENCY_REFERENCE for empty or malformed refs', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          { name: 'pkg', version: '1.0.0', 'bom-ref': 'ref-pkg', purl: 'pkg:npm/pkg@1.0.0' },
        ],
        dependencies: [
          {
            ref: '   ', // empty parent ref
            dependsOn: ['ref-pkg'],
          },
          {
            ref: 'ref-pkg',
            dependsOn: [''], // empty child ref
          },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const invalidRefs = anomalies.filter(a => a.type === AnomalyType.INVALID_DEPENDENCY_REFERENCE);

      assert.ok(invalidRefs.length >= 2);
      for (const a of invalidRefs) {
        assert.equal(a.severity, AnomalySeverity.ERROR);
      }
    });

    it('detects MISSING_DEPENDENCY_RELATIONSHIP when root has no dependency entry or components are orphans', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: {
          component: { name: 'app', version: '1.0.0', 'bom-ref': 'ref-root', purl: 'pkg:npm/app@1.0.0' },
        },
        components: [
          { name: 'orphan-pkg', version: '1.0.0', 'bom-ref': 'ref-orphan', purl: 'pkg:npm/orphan-pkg@1.0.0' },
        ],
        dependencies: [], // root is missing, orphan-pkg is unlinked
      };

      const anomalies = detectAnomalies(sbom);
      const missingRel = anomalies.filter(a => a.type === AnomalyType.MISSING_DEPENDENCY_RELATIONSHIP);

      assert.ok(missingRel.length >= 1);
      assert.equal(missingRel[0].severity, AnomalySeverity.WARNING);
    });
  });

  describe('First-Party and Workspace Components', () => {
    it('analyzes root application in metadata.component correctly', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        metadata: {
          component: {
            type: 'application',
            name: '', // missing name in root
            version: 'invalid.ver',
            'bom-ref': 'root-ref',
          },
        },
      };

      const anomalies = detectAnomalies(sbom);
      assert.ok(anomalies.some(a => a.type === AnomalyType.MISSING_NAME && a.source === 'metadata.component'));
      assert.ok(anomalies.some(a => a.type === AnomalyType.INVALID_VERSION && a.source === 'metadata.component'));
    });

    it('identifies missing metadata in workspace components', () => {
      const scanResult = {
        status: 'complete',
        components: [
          {
            name: 'root-app',
            version: '1.0.0',
            isRoot: true,
            bomRef: 'pkg:npm/root-app@1.0.0',
            purl: 'pkg:npm/root-app@1.0.0',
          },
          {
            name: 'workspace-a',
            // missing version in workspace package
            dependencyType: 'workspace',
            isFirstParty: true,
            bomRef: 'pkg:npm/workspace-a',
            purl: 'pkg:npm/workspace-a',
          },
        ],
        dependencyEdges: {
          'pkg:npm/root-app@1.0.0': ['pkg:npm/workspace-a'],
          'pkg:npm/workspace-a': [],
        },
      };

      const anomalies = detectAnomalies(scanResult);
      assert.ok(anomalies.some(a => a.type === AnomalyType.MISSING_VERSION && a.component.name === 'workspace-a'));
    });
  });

  describe('Output Behavior, Immutability & Deduplication', () => {
    it('returns an empty array when SBOM is null, undefined, or empty', () => {
      assert.deepEqual(detectAnomalies(null), []);
      assert.deepEqual(detectAnomalies(undefined), []);
      assert.deepEqual(detectAnomalies({}), []);
      assert.deepEqual(detectAnomalies([]), []);
    });

    it('does not mutate the input SBOM object', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          { name: 'pkg', version: 'invalid-ver', 'bom-ref': 'ref-1', purl: 'pkg:npm/pkg@invalid-ver' },
        ],
        dependencies: [
          { ref: 'ref-1', dependsOn: ['nonexistent'] },
        ],
      };

      const sbomBefore = JSON.stringify(sbom);
      detectAnomalies(sbom);
      const sbomAfter = JSON.stringify(sbom);

      assert.equal(sbomBefore, sbomAfter);
    });

    it('produces deterministic output across multiple invocations', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          { name: 'b-pkg', version: 'invalid-ver', 'bom-ref': 'b-ref' },
          { name: 'a-pkg', version: '', 'bom-ref': 'a-ref' },
        ],
        dependencies: [
          { ref: 'b-ref', dependsOn: ['ghost'] },
        ],
      };

      const run1 = detectAnomalies(sbom);
      const run2 = detectAnomalies(sbom);

      assert.deepEqual(run1, run2);
      assert.equal(run1[0].id, 'ANOMALY-001');
      assert.equal(run1[1].id, 'ANOMALY-002');
    });

    it('deduplicates identical anomaly records on the same component', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          { name: 'dup-pkg', version: '1.0.0', 'bom-ref': 'ref-1', purl: 'pkg:npm/dup-pkg@1.0.0' },
        ],
        dependencies: [
          { ref: 'ref-1', dependsOn: ['ghost', 'ghost'] },
        ],
      };

      const anomalies = detectAnomalies(sbom);
      const unresolvedGhost = anomalies.filter(
        a => a.type === AnomalyType.UNRESOLVED_DEPENDENCY && a.dependencyRef === 'ghost'
      );

      // Should be deduplicated to 1 record for unresolved 'ghost'
      assert.equal(unresolvedGhost.length, 1);
    });

    it('computes summary with options.summary: true and summarizeAnomalies helper', () => {
      const sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        components: [
          { name: '', version: 'bad.ver', 'bom-ref': 'ref-1' },
        ],
      };

      const result = detectAnomalies(sbom, { summary: true });
      assert.ok(result.anomalies);
      assert.ok(result.summary);
      assert.ok(result.summary.total > 0);
      assert.ok(result.summary.bySeverity[AnomalySeverity.ERROR] > 0);

      const standaloneSummary = summarizeAnomalies(result.anomalies);
      assert.deepEqual(standaloneSummary, result.summary);
    });
  });
});

