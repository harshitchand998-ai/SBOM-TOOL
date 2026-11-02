import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildDependencyGraph } from '../src/dependencyGraph.js';

/**
 * Helper to create a minimal component for testing.
 */
function makeComponent(name, version, isRoot = false) {
  const purl = `pkg:npm/${name}@${version}`;
  return {
    name,
    version,
    ecosystem: 'npm',
    purl,
    bomRef: purl,
    dependencyType: isRoot ? 'root' : 'transitive',
    dependencyGroups: [],
    integrity: null,
    resolved: null,
    installPaths: isRoot ? [] : [`node_modules/${name}`],
    optional: false,
    dev: false,
    devOptional: false,
    ...(isRoot && { isRoot: true }),
  };
}

/**
 * Helper to set up components and keyToBomRef from a packages object.
 */
function setupFromPackages(rootName, rootVersion, packages) {
  const rootRef = `pkg:npm/${rootName}@${rootVersion}`;
  const components = new Map();
  const keyToBomRef = new Map();

  components.set(rootRef, makeComponent(rootName, rootVersion, true));

  for (const [lockKey, entry] of Object.entries(packages)) {
    if (lockKey === '') continue;
    if (!entry.version) continue;
    const name = lockKey.split('node_modules/').pop();
    const purl = `pkg:npm/${name}@${entry.version}`;
    if (!components.has(purl)) {
      components.set(purl, makeComponent(name, entry.version));
    }
    keyToBomRef.set(lockKey, purl);
  }

  return { components, keyToBomRef, rootRef };
}

describe('Dependency Graph Builder', () => {
  describe('direct dependency relationships', () => {
    it('creates edges from root to direct dependencies', () => {
      const packages = {
        '': { name: 'my-app', version: '1.0.0', dependencies: { 'is-odd': '3.0.1' } },
        'node_modules/is-odd': { version: '3.0.1' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('my-app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { 'is-odd': '3.0.1' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'my-app',
      });

      const rootEdges = result.dependencyEdges.get(rootRef);
      assert.ok(rootEdges.has('pkg:npm/is-odd@3.0.1'), 'Root should depend on is-odd');
      assert.equal(rootEdges.size, 1);
    });
  });

  describe('transitive dependency relationships', () => {
    it('creates edges for multi-level chains', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { accepts: '1.3.8' } },
        'node_modules/accepts': {
          version: '1.3.8',
          dependencies: { 'mime-types': '~2.1.34' },
        },
        'node_modules/mime-types': {
          version: '2.1.35',
          dependencies: { 'mime-db': '1.52.0' },
        },
        'node_modules/mime-db': { version: '1.52.0' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { accepts: '1.3.8' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      const acceptsEdges = result.dependencyEdges.get('pkg:npm/accepts@1.3.8');
      assert.ok(acceptsEdges.has('pkg:npm/mime-types@2.1.35'), 'accepts → mime-types');

      const mimeTypesEdges = result.dependencyEdges.get('pkg:npm/mime-types@2.1.35');
      assert.ok(mimeTypesEdges.has('pkg:npm/mime-db@1.52.0'), 'mime-types → mime-db');

      const mimeDbEdges = result.dependencyEdges.get('pkg:npm/mime-db@1.52.0');
      assert.equal(mimeDbEdges.size, 0, 'mime-db is a leaf');
    });
  });

  describe('nested dependency relationships', () => {
    it('resolves nested node_modules paths for version conflicts', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { 'parent-a': '1.0.0', 'parent-b': '1.0.0' } },
        'node_modules/parent-a': {
          version: '1.0.0',
          dependencies: { 'shared': '^1.0.0' },
        },
        'node_modules/parent-b': {
          version: '1.0.0',
          dependencies: { 'shared': '^2.0.0' },
        },
        'node_modules/shared': { version: '1.5.0' },
        'node_modules/parent-b/node_modules/shared': { version: '2.0.0' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { 'parent-a': '1.0.0', 'parent-b': '1.0.0' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      const parentAEdges = result.dependencyEdges.get('pkg:npm/parent-a@1.0.0');
      assert.ok(parentAEdges.has('pkg:npm/shared@1.5.0'), 'parent-a → shared@1.5.0');

      const parentBEdges = result.dependencyEdges.get('pkg:npm/parent-b@1.0.0');
      assert.ok(parentBEdges.has('pkg:npm/shared@2.0.0'), 'parent-b → shared@2.0.0');
    });
  });

  describe('multiple installed versions of the same package', () => {
    it('preserves separate nodes and distinct edges', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { a: '1.0.0', b: '1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { dep: '^1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { dep: '^2.0.0' } },
        'node_modules/dep': { version: '1.0.0' },
        'node_modules/b/node_modules/dep': { version: '2.0.0' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { a: '1.0.0', b: '1.0.0' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      assert.ok(components.has('pkg:npm/dep@1.0.0'), 'dep@1.0.0 exists');
      assert.ok(components.has('pkg:npm/dep@2.0.0'), 'dep@2.0.0 exists');

      const aEdges = result.dependencyEdges.get('pkg:npm/a@1.0.0');
      assert.ok(aEdges.has('pkg:npm/dep@1.0.0'), 'a → dep@1.0.0');
      assert.ok(!aEdges.has('pkg:npm/dep@2.0.0'), 'a should NOT link to dep@2.0.0');

      const bEdges = result.dependencyEdges.get('pkg:npm/b@1.0.0');
      assert.ok(bEdges.has('pkg:npm/dep@2.0.0'), 'b → dep@2.0.0');
      assert.ok(!bEdges.has('pkg:npm/dep@1.0.0'), 'b should NOT link to dep@1.0.0');
    });
  });

  describe('packages with no dependencies', () => {
    it('produces empty edge sets for leaf packages', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { ms: '2.1.3' } },
        'node_modules/ms': { version: '2.1.3' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { ms: '2.1.3' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      const msEdges = result.dependencyEdges.get('pkg:npm/ms@2.1.3');
      assert.equal(msEdges.size, 0, 'ms has no children');
    });

    it('handles zero-dependency projects', () => {
      const packages = {
        '': { name: 'empty-app', version: '1.0.0' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('empty-app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: {}, rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'empty-app',
      });

      assert.equal(result.dependencyEdges.get(rootRef).size, 0);
      assert.equal(result.warnings.length, 0);
    });
  });

  describe('unresolved dependency references', () => {
    it('generates warnings for unresolvable dependencies', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { ms: '2.1.3', missing: '^1.0.0' } },
        'node_modules/ms': { version: '2.1.3' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { ms: '2.1.3', missing: '^1.0.0' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      const unresolved = result.warnings.filter(w => w.code === 'UNRESOLVED_DEPENDENCY');
      assert.ok(unresolved.length > 0, 'Should have unresolved warnings');
      assert.ok(unresolved.some(w => w.dependency === 'missing'), 'Should warn about missing');

      // ms should still be linked
      assert.ok(result.dependencyEdges.get(rootRef).has('pkg:npm/ms@2.1.3'));
    });
  });

  describe('edge integrity', () => {
    it('every edge references an existing component bomRef', () => {
      const packages = {
        '': { name: 'app', version: '1.0.0', dependencies: { accepts: '1.3.8' } },
        'node_modules/accepts': {
          version: '1.3.8',
          dependencies: { 'mime-types': '~2.1.34', negotiator: '0.6.3' },
        },
        'node_modules/mime-types': {
          version: '2.1.35',
          dependencies: { 'mime-db': '1.52.0' },
        },
        'node_modules/mime-db': { version: '1.52.0' },
        'node_modules/negotiator': { version: '0.6.3' },
      };
      const { components, keyToBomRef, rootRef } = setupFromPackages('app', '1.0.0', packages);

      const result = buildDependencyGraph({
        components, keyToBomRef, packages, rootRef,
        rootDeps: { accepts: '1.3.8' },
        rootDevDeps: {}, rootOptDeps: {}, rootPeerDeps: {},
        rootName: 'app',
      });

      for (const [parentRef, childRefs] of result.dependencyEdges) {
        assert.ok(components.has(parentRef), `Parent bomRef "${parentRef}" must exist in components`);
        for (const childRef of childRefs) {
          assert.ok(components.has(childRef), `Child bomRef "${childRef}" must exist in components`);
        }
      }
    });
  });
});
