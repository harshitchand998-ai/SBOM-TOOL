/**
 * Tests for Dependency Comparison Module (Order 15)
 * Verifies component matching, version upgrades/downgrades, metadata changes,
 * missing/duplicate/unresolvable metadata, immutability, and error handling.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  compareInventories,
  ComparisonStatus,
  ChangeType,
  scanProject,
} from '../src/index.js';

function makeBom(components = [], rootName = 'test-app') {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        name: rootName,
        version: '1.0.0',
        'bom-ref': `pkg:npm/${rootName}@1.0.0`,
        purl: `pkg:npm/${rootName}@1.0.0`,
      },
    },
    components,
  };
}

function makePkg(name, version, extra = {}) {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  const purl = version ? `pkg:npm/${encodedName}@${version}` : `pkg:npm/${encodedName}`;
  return {
    type: 'library',
    name,
    ...(version !== undefined ? { version } : {}),
    'bom-ref': purl,
    purl,
    ...extra,
  };
}

describe('Dependency Comparison (compareInventories)', () => {

  it('1. Two identical SBOMs — reports all components as unchanged and zero changes', () => {
    const prev = makeBom([
      makePkg('lodash', '4.17.21'),
      makePkg('@babel/core', '7.24.0'),
    ]);
    const curr = makeBom([
      makePkg('lodash', '4.17.21'),
      makePkg('@babel/core', '7.24.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 2 });
    assert.equal(result.added.length, 0);
    assert.equal(result.removed.length, 0);
    assert.equal(result.changed.length, 0);
    assert.equal(result.unchanged.length, 2);
    assert.equal(result.errors.length, 0);
    assert.ok(result.unchanged[0].explanation.includes('unchanged'));
  });

  it('2. One newly added dependency — classifies component in added with explanation', () => {
    const prev = makeBom([makePkg('lodash', '4.17.21')]);
    const curr = makeBom([makePkg('lodash', '4.17.21'), makePkg('express', '4.19.2')]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 1, removed: 0, changed: 0, unchanged: 1 });
    assert.equal(result.added.length, 1);
    assert.equal(result.added[0].name, 'express');
    assert.equal(result.added[0].version, '4.19.2');
    assert.equal(result.added[0].changeType, ChangeType.ADDED);
    assert.ok(result.added[0].explanation.includes('Added express@4.19.2'));
  });

  it('3. One removed dependency — classifies component in removed with explanation', () => {
    const prev = makeBom([makePkg('lodash', '4.17.21'), makePkg('underscore', '1.13.6')]);
    const curr = makeBom([makePkg('lodash', '4.17.21')]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 1, changed: 0, unchanged: 1 });
    assert.equal(result.removed.length, 1);
    assert.equal(result.removed[0].name, 'underscore');
    assert.equal(result.removed[0].version, '1.13.6');
    assert.equal(result.removed[0].changeType, ChangeType.REMOVED);
    assert.ok(result.removed[0].explanation.includes('Removed underscore@1.13.6'));
  });

  it('4. One upgraded dependency — matches by package identity and reports upgrade (not remove+add)', () => {
    const prev = makeBom([makePkg('lodash', '4.17.20')]);
    const curr = makeBom([makePkg('lodash', '4.17.21')]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 1, unchanged: 0 });
    assert.equal(result.changed.length, 1);

    const c = result.changed[0];
    assert.equal(c.name, 'lodash');
    assert.equal(c.changeType, ChangeType.UPGRADE);
    assert.equal(c.previousVersion, '4.17.20');
    assert.equal(c.currentVersion, '4.17.21');
    assert.equal(c.previousComponent.version, '4.17.20');
    assert.equal(c.currentComponent.version, '4.17.21');
    assert.ok(c.changedFields.includes('version'));
    assert.ok(c.explanation.includes('Upgraded lodash from 4.17.20 to 4.17.21'));
  });

  it('5. One downgraded dependency — accurately detects SemVer downgrade including prereleases', () => {
    const prev = makeBom([makePkg('express', '5.0.0'), makePkg('alpha-pkg', '2.0.0')]);
    const curr = makeBom([makePkg('express', '4.19.2'), makePkg('alpha-pkg', '2.0.0-rc.1')]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 2, unchanged: 0 });
    for (const item of result.changed) {
      assert.equal(item.changeType, ChangeType.DOWNGRADE);
      assert.ok(item.explanation.includes('Downgraded'));
    }
  });

  it('6. Multiple added and removed dependencies — counts and classifies all entries accurately', () => {
    const prev = makeBom([
      makePkg('keep-pkg', '1.0.0'),
      makePkg('old-a', '1.0.0'),
      makePkg('old-b', '2.0.0'),
    ]);
    const curr = makeBom([
      makePkg('keep-pkg', '1.0.0'),
      makePkg('new-x', '1.2.3'),
      makePkg('new-y', '4.5.6'),
      makePkg('new-z', '0.1.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 3, removed: 2, changed: 0, unchanged: 1 });
    assert.deepEqual(result.added.map(a => a.name).sort(), ['new-x', 'new-y', 'new-z']);
    assert.deepEqual(result.removed.map(r => r.name).sort(), ['old-a', 'old-b']);
  });

  it('7. Multiple changed dependencies — mixes upgrades, downgrades, and metadata changes cleanly', () => {
    const prev = makeBom([
      makePkg('up-pkg', '1.0.0'),
      makePkg('down-pkg', '3.0.0'),
      makePkg('meta-pkg', '1.5.0', { hashes: [{ alg: 'SHA-512', content: 'oldhash' }] }),
      makePkg('same-pkg', '2.0.0'),
    ]);
    const curr = makeBom([
      makePkg('up-pkg', '1.1.0'),
      makePkg('down-pkg', '2.9.0'),
      makePkg('meta-pkg', '1.5.0', { hashes: [{ alg: 'SHA-512', content: 'newhash' }] }),
      makePkg('same-pkg', '2.0.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 3, unchanged: 1 });

    const byName = new Map(result.changed.map(c => [c.name, c]));
    assert.equal(byName.get('up-pkg').changeType, ChangeType.UPGRADE);
    assert.equal(byName.get('down-pkg').changeType, ChangeType.DOWNGRADE);
    assert.equal(byName.get('meta-pkg').changeType, ChangeType.METADATA_CHANGED);
  });

  it('8. Metadata changes without version changes — detects hashes, externalReferences, and license updates', () => {
    const prev = makeBom([
      makePkg('lib-a', '1.0.0', {
        externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/lib-a-1.0.0.tgz' }],
        licenses: [{ license: { id: 'MIT' } }],
      }),
    ]);
    const curr = makeBom([
      makePkg('lib-a', '1.0.0', {
        externalReferences: [{ type: 'distribution', url: 'https://mirror.example.com/lib-a-1.0.0.tgz' }],
        licenses: [{ license: { id: 'Apache-2.0' } }],
      }),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 1, unchanged: 0 });
    assert.equal(result.changed[0].changeType, ChangeType.METADATA_CHANGED);
    assert.equal(result.changed[0].previousVersion, '1.0.0');
    assert.equal(result.changed[0].currentVersion, '1.0.0');
    assert.ok(result.changed[0].changedFields.includes('externalReferences'));
    assert.ok(result.changed[0].changedFields.includes('licenses'));
  });

  it('9. Missing PURLs — falls back cleanly to package name and ecosystem for matching', () => {
    const prev = makeBom([
      { type: 'library', name: 'no-purl-pkg', version: '1.0.0', 'bom-ref': 'ref-1' },
      { type: 'library', name: '@org/scoped', version: '2.0.0' },
    ]);
    const curr = makeBom([
      { type: 'library', name: 'no-purl-pkg', version: '1.2.0', 'bom-ref': 'ref-1' },
      { type: 'library', name: '@org/scoped', version: '2.0.0' },
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 1, unchanged: 1 });
    assert.equal(result.changed[0].name, 'no-purl-pkg');
    assert.equal(result.changed[0].changeType, ChangeType.UPGRADE);
    assert.equal(result.unchanged[0].name, '@org/scoped');
  });

  it('10. Missing or non-comparable versions — avoids inventing upgrade/downgrade and emits warning', () => {
    const prev = makeBom([
      { type: 'library', name: 'missing-ver-prev', 'bom-ref': 'a' },
      { type: 'library', name: 'git-dep', version: 'git+https://github.com/org/repo#abc', 'bom-ref': 'b' },
      { type: 'library', name: 'both-missing', 'bom-ref': 'c' },
    ]);
    const curr = makeBom([
      { type: 'library', name: 'missing-ver-prev', version: '1.0.0', 'bom-ref': 'a' },
      { type: 'library', name: 'git-dep', version: '1.0.0', 'bom-ref': 'b' },
      { type: 'library', name: 'both-missing', 'bom-ref': 'c' },
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 2, unchanged: 1 });

    const byName = new Map(result.changed.map(c => [c.name, c]));
    assert.equal(byName.get('missing-ver-prev').changeType, ChangeType.VERSION_CHANGED);
    assert.equal(byName.get('git-dep').changeType, ChangeType.VERSION_CHANGED);
    assert.ok(result.warnings.filter(w => w.code === 'NON_COMPARABLE_VERSIONS').length === 2);
  });

  it('11. Duplicate component identifiers & multi-version packages — preserves entries without silent loss and warns', () => {
    const prev = makeBom([
      makePkg('shared-dep', '1.5.0'),
      makePkg('shared-dep', '2.0.0'),
      makePkg('dup-pkg', '1.0.0'),
      makePkg('dup-pkg', '1.0.0'),
    ]);
    const curr = makeBom([
      makePkg('shared-dep', '1.5.0'),
      makePkg('shared-dep', '2.1.0'),
      makePkg('dup-pkg', '1.0.0'),
      makePkg('dup-pkg', '1.0.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    // shared-dep@1.5.0 unchanged, shared-dep@2.0.0 -> 2.1.0 upgraded, both dup-pkg@1.0.0 unchanged
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 1, unchanged: 3 });
    assert.equal(result.changed[0].name, 'shared-dep');
    assert.equal(result.changed[0].changeType, ChangeType.UPGRADE);
    assert.equal(result.changed[0].previousVersion, '2.0.0');
    assert.equal(result.changed[0].currentVersion, '2.1.0');

    const dupWarnings = result.warnings.filter(w => w.code === 'DUPLICATE_COMPONENT_IDENTIFIER');
    assert.ok(dupWarnings.length >= 2, 'Should warn about duplicate identifiers in previous and current');
  });

  it('12. Empty previous inventory — marks all current components as added', () => {
    const prev = makeBom([]);
    const curr = makeBom([makePkg('a', '1.0.0'), makePkg('b', '2.0.0')]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 2, removed: 0, changed: 0, unchanged: 0 });
    assert.equal(result.added.length, 2);
  });

  it('13. Empty current inventory — marks all previous components as removed', () => {
    const prev = makeBom([makePkg('a', '1.0.0'), makePkg('b', '2.0.0')]);
    const curr = makeBom([]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 2, changed: 0, unchanged: 0 });
    assert.equal(result.removed.length, 2);
  });

  it('14. Both inventories empty — completes cleanly with zero counts', () => {
    const prev = makeBom([]);
    const curr = makeBom([]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 0 });
    assert.equal(result.errors.length, 0);
  });

  it('15. Invalid previous SBOM — fails gracefully with structured error without crashing', () => {
    const curr = makeBom([makePkg('a', '1.0.0')]);

    for (const badPrev of [null, undefined, 'string', 42, [], {}, { bomFormat: 'CycloneDX', components: 'bad' }]) {
      const result = compareInventories(badPrev, curr);
      assert.equal(result.status, ComparisonStatus.FAILED);
      assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 0 });
      assert.ok(result.errors.length >= 1);
      assert.equal(result.errors[0].target, 'previous');
    }
  });

  it('16. Invalid current SBOM — fails gracefully with structured error without crashing', () => {
    const prev = makeBom([makePkg('a', '1.0.0')]);

    for (const badCurr of [null, undefined, [], {}, { status: 'failed', components: [] }]) {
      const result = compareInventories(prev, badCurr);
      assert.equal(result.status, ComparisonStatus.FAILED);
      assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 0 });
      assert.ok(result.errors.length >= 1);
      assert.equal(result.errors[0].target, 'current');
    }
  });

  it('17. Unresolvable component identity — warns and skips unidentifiable component without crashing', () => {
    const prev = makeBom([
      { type: 'library', version: '1.0.0' }, // no name, no purl
      makePkg('valid-pkg', '1.0.0'),
    ]);
    const curr = makeBom([
      { type: 'library', name: '', purl: 'invalid-purl', version: '1.0.0' }, // empty name and invalid purl
      makePkg('valid-pkg', '1.0.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 1 });
    assert.ok(result.warnings.some(w => w.code === 'UNRESOLVABLE_COMPONENT_IDENTITY'));
  });

  it('18. First-party components — tracks workspace/application component additions and upgrades', () => {
    const prev = makeBom([
      makePkg('@myorg/ws-a', '1.0.0', { isFirstParty: true, dependencyType: 'workspace' }),
      makePkg('lodash', '4.17.21'),
    ]);
    const curr = makeBom([
      makePkg('@myorg/ws-a', '1.1.0', { isFirstParty: true, dependencyType: 'workspace' }),
      makePkg('@myorg/ws-b', '0.1.0', { isFirstParty: true, dependencyType: 'workspace' }),
      makePkg('lodash', '4.17.21'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 1, removed: 0, changed: 1, unchanged: 1 });
    assert.equal(result.changed[0].name, '@myorg/ws-a');
    assert.equal(result.changed[0].changeType, ChangeType.UPGRADE);
    assert.equal(result.changed[0].currentComponent.isFirstParty, true);
    assert.equal(result.added[0].name, '@myorg/ws-b');
    assert.equal(result.added[0].component.isFirstParty, true);
  });

  it('19. Third-party components — integrates cleanly with real scanProject() BOM outputs', async () => {
    const simpleScan = await scanProject('./fixtures/simple-project');
    const zeroScan = await scanProject('./fixtures/zero-deps-project');

    const result = compareInventories(zeroScan.bom, simpleScan.bom);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.equal(result.summary.added, 2); // is-odd and is-number
    assert.equal(result.summary.removed, 0);
    assert.equal(result.summary.changed, 0);
    assert.equal(result.summary.unchanged, 0);
    assert.deepEqual(result.added.map(a => a.name).sort(), ['is-number', 'is-odd']);

    // Comparing identical scanResult objects directly also works identically
    const sameResult = compareInventories(simpleScan, simpleScan);
    assert.equal(sameResult.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(sameResult.summary, { added: 0, removed: 0, changed: 0, unchanged: 2 });
  });

  it('20. Components with different identifiers (bom-ref / PURL presence / ecosystem) match appropriately', () => {
    const prev = makeBom([
      // Matched across different bom-refs and PURL qualifiers
      {
        type: 'library',
        name: 'debug',
        version: '4.3.4',
        'bom-ref': 'custom-ref-1',
        purl: 'pkg:npm/debug@4.3.4?vcs_url=git+https://github.com/debug-js/debug',
      },
      // Matched even when current SBOM dropped its PURL
      {
        type: 'library',
        name: 'ms',
        version: '2.1.2',
        'bom-ref': 'ref-ms-1',
        purl: 'pkg:npm/ms@2.1.2',
      },
      // Different ecosystems with identical name should NOT match each other
      {
        type: 'library',
        name: 'requests',
        version: '2.28.0',
        ecosystem: 'pypi',
        'bom-ref': 'pkg:pypi/requests@2.28.0',
        purl: 'pkg:pypi/requests@2.28.0',
      },
    ]);

    const curr = makeBom([
      {
        type: 'library',
        name: 'debug',
        version: '4.3.5',
        'bom-ref': 'custom-ref-999',
        purl: 'pkg:npm/debug@4.3.5',
      },
      {
        type: 'library',
        name: 'ms',
        version: '2.1.2',
        'bom-ref': 'ref-ms-2',
      },
      {
        type: 'library',
        name: 'requests',
        version: '1.0.0',
        ecosystem: 'npm',
        'bom-ref': 'pkg:npm/requests@1.0.0',
        purl: 'pkg:npm/requests@1.0.0',
      },
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 1, removed: 1, changed: 2, unchanged: 0 });

    const debugChange = result.changed.find(c => c.name === 'debug');
    assert.equal(debugChange.changeType, ChangeType.UPGRADE);

    const msChange = result.changed.find(c => c.name === 'ms');
    assert.equal(msChange.changeType, ChangeType.METADATA_CHANGED);
    assert.ok(msChange.changedFields.includes('purl'));

    assert.equal(result.removed[0].ecosystem, 'pypi');
    assert.equal(result.removed[0].name, 'requests');
    assert.equal(result.added[0].ecosystem, 'npm');
    assert.equal(result.added[0].name, 'requests');
  });

  it('21. Does not mutate input SBOM objects', () => {
    const prev = makeBom([makePkg('a', '1.0.0')]);
    const curr = makeBom([makePkg('a', '2.0.0'), makePkg('b', '1.0.0')]);

    const prevBefore = JSON.stringify(prev);
    const currBefore = JSON.stringify(curr);

    compareInventories(prev, curr);

    assert.equal(JSON.stringify(prev), prevBefore);
    assert.equal(JSON.stringify(curr), currBefore);
  });

  it('22. Multi-version upgrades across minor >= 10 sort by SemVer precedence without false downgrades', () => {
    const prev = makeBom([
      makePkg('multi', '1.9.0'),
      makePkg('multi', '1.2.0'),
    ]);
    const curr = makeBom([
      makePkg('multi', '1.10.0'),
      makePkg('multi', '1.3.0'),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 2, unchanged: 0 });
    for (const item of result.changed) {
      assert.equal(item.changeType, ChangeType.UPGRADE);
    }
    const pair1 = result.changed.find(c => c.previousVersion === '1.2.0');
    const pair2 = result.changed.find(c => c.previousVersion === '1.9.0');
    assert.equal(pair1.currentVersion, '1.3.0');
    assert.equal(pair2.currentVersion, '1.10.0');
  });

  it('23. Duplicate packages with identical versions preserve unchanged vs metadata-changed independently', () => {
    const prev = makeBom([
      makePkg('dup', '1.0.0', { hashes: [{ alg: 'SHA-512', content: 'hash-a' }] }),
      makePkg('dup', '1.0.0', { hashes: [{ alg: 'SHA-512', content: 'hash-b' }] }),
    ]);
    const curr = makeBom([
      makePkg('dup', '1.0.0', { hashes: [{ alg: 'SHA-512', content: 'hash-c' }] }),
      makePkg('dup', '1.0.0', { hashes: [{ alg: 'SHA-512', content: 'hash-a' }] }),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 1, unchanged: 1 });
    assert.equal(result.unchanged[0].component.hashes[0].content, 'hash-a');
    assert.equal(result.changed[0].changeType, ChangeType.METADATA_CHANGED);
    assert.equal(result.changed[0].previousComponent.hashes[0].content, 'hash-b');
    assert.equal(result.changed[0].currentComponent.hashes[0].content, 'hash-c');
    assert.ok(result.warnings.some(w => w.code === 'DUPLICATE_COMPONENT_IDENTIFIER'));
  });

  it('24. Prevents unknown ecosystems from being silently labeled as npm and warns on ambiguous matches', () => {
    const prev = makeBom([
      { type: 'library', name: 'mystery-lib', version: '1.0', 'bom-ref': 'ref-1' },
      { type: 'library', name: 'poly', version: '1.0.0', purl: 'pkg:npm/poly@1.0.0', 'bom-ref': 'npm-poly' },
      { type: 'library', name: 'poly', version: '2.0.0', purl: 'pkg:pypi/poly@2.0.0', 'bom-ref': 'pypi-poly' },
    ]);
    const curr = makeBom([
      { type: 'library', name: 'mystery-lib', version: '1.1', 'bom-ref': 'ref-1' },
      { type: 'library', name: 'poly', version: '3.0.0', 'bom-ref': 'unknown-poly' },
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    const mystery = result.changed.find(c => c.name === 'mystery-lib');
    assert.equal(mystery.ecosystem, 'unknown');
    assert.equal(mystery.changeType, ChangeType.VERSION_CHANGED);
    assert.ok(result.warnings.some(w => w.code === 'NON_COMPARABLE_VERSIONS'));
    assert.ok(result.warnings.some(w => w.code === 'AMBIGUOUS_COMPONENT_MATCH'));
  });

  it('25. Metadata arrays with identical values in different orders do not report false metadata-changed', () => {
    const prev = makeBom([
      makePkg('ordered-meta', '1.0.0', {
        hashes: [
          { alg: 'SHA-256', content: 'aaa' },
          { alg: 'SHA-512', content: 'bbb' },
        ],
        licenses: [{ license: { id: 'MIT' } }, { license: { id: 'Apache-2.0' } }],
        properties: [
          { name: 'env', value: 'prod' },
          { name: 'tier', value: 'core' },
        ],
      }),
    ]);
    const curr = makeBom([
      makePkg('ordered-meta', '1.0.0', {
        hashes: [
          { alg: 'SHA-512', content: 'bbb' },
          { alg: 'SHA-256', content: 'aaa' },
        ],
        licenses: [{ license: { id: 'Apache-2.0' } }, { license: { id: 'MIT' } }],
        properties: [
          { name: 'tier', value: 'core' },
          { name: 'env', value: 'prod' },
        ],
      }),
    ]);

    const result = compareInventories(prev, curr);

    assert.equal(result.status, ComparisonStatus.COMPLETED);
    assert.deepEqual(result.summary, { added: 0, removed: 0, changed: 0, unchanged: 1 });
    assert.equal(result.changed.length, 0);
  });

  it('26. Mutating returned snapshots does not affect input SBOM metadata arrays', () => {
    const prev = makeBom([
      makePkg('safe-snap', '1.0.0', { hashes: [{ alg: 'SHA-256', content: 'orig' }] }),
    ]);
    const curr = makeBom([
      makePkg('safe-snap', '1.0.0', { hashes: [{ alg: 'SHA-256', content: 'orig' }] }),
    ]);

    const result = compareInventories(prev, curr);
    result.unchanged[0].component.hashes[0].content = 'tampered';

    assert.equal(prev.components[0].hashes[0].content, 'orig');
    assert.equal(curr.components[0].hashes[0].content, 'orig');
  });
});

