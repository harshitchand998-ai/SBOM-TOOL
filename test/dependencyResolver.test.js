import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parsePackageJson, parsePackageLock } from '../src/parser.js';
import { resolveDependencies, resolveManifestOnly } from '../src/dependencyResolver.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

/**
 * Helper to parse and resolve a fixture project.
 */
function resolveFixture(fixtureName) {
  const pkgResult = parsePackageJson(path.join(fixturesDir, fixtureName, 'package.json'));
  const lockResult = parsePackageLock(path.join(fixturesDir, fixtureName, 'package-lock.json'));
  assert.equal(pkgResult.errors.length, 0, `${fixtureName}: package.json parse errors`);
  assert.equal(lockResult.errors.length, 0, `${fixtureName}: lockfile parse errors`);
  return resolveDependencies(pkgResult.data, lockResult.data);
}

describe('Dependency Resolver', () => {
  describe('simple-project', () => {
    it('discovers direct and transitive dependencies', () => {
      const result = resolveFixture('simple-project');

      // Should have root + is-odd (direct) + is-number (transitive) = 3 components
      assert.equal(result.components.size, 3, 'Should have 3 components');

      const isOdd = [...result.components.values()].find(c => c.name === 'is-odd');
      assert.ok(isOdd, 'is-odd should be found');
      assert.equal(isOdd.version, '3.0.1');
      assert.equal(isOdd.dependencyType, 'direct');
      assert.deepEqual(isOdd.dependencyGroups, ['dependencies']);

      const isNumber = [...result.components.values()].find(c => c.name === 'is-number');
      assert.ok(isNumber, 'is-number should be found');
      assert.equal(isNumber.version, '6.0.0');
      assert.equal(isNumber.dependencyType, 'transitive');
    });

    it('builds correct dependency edges', () => {
      const result = resolveFixture('simple-project');

      // Root → is-odd
      const rootDeps = result.dependencyEdges.get(result.rootRef);
      assert.ok(rootDeps, 'Root should have dependency edges');
      assert.equal(rootDeps.size, 1);

      const isOddRef = [...result.components.values()].find(c => c.name === 'is-odd').bomRef;
      assert.ok(rootDeps.has(isOddRef), 'Root should depend on is-odd');

      // is-odd → is-number
      const isOddDeps = result.dependencyEdges.get(isOddRef);
      assert.ok(isOddDeps, 'is-odd should have dependency edges');
      const isNumberRef = [...result.components.values()].find(c => c.name === 'is-number').bomRef;
      assert.ok(isOddDeps.has(isNumberRef), 'is-odd should depend on is-number');

      // is-number → nothing (leaf)
      const isNumberDeps = result.dependencyEdges.get(isNumberRef);
      assert.equal(isNumberDeps.size, 0, 'is-number is a leaf node');
    });
  });

  describe('transitive-project', () => {
    it('discovers multi-level transitive dependencies', () => {
      const result = resolveFixture('transitive-project');

      // Root + accepts + mime-types + mime-db + negotiator = 5
      assert.equal(result.components.size, 5, 'Should have 5 components');

      const accepts = [...result.components.values()].find(c => c.name === 'accepts');
      assert.ok(accepts);
      assert.equal(accepts.dependencyType, 'direct');

      const mimeTypes = [...result.components.values()].find(c => c.name === 'mime-types');
      assert.ok(mimeTypes);
      assert.equal(mimeTypes.dependencyType, 'transitive');

      const mimeDb = [...result.components.values()].find(c => c.name === 'mime-db');
      assert.ok(mimeDb);
      assert.equal(mimeDb.dependencyType, 'transitive');

      const negotiator = [...result.components.values()].find(c => c.name === 'negotiator');
      assert.ok(negotiator);
      assert.equal(negotiator.dependencyType, 'transitive');
    });

    it('preserves dependency chain: accepts → mime-types → mime-db', () => {
      const result = resolveFixture('transitive-project');

      const accepts = [...result.components.values()].find(c => c.name === 'accepts');
      const mimeTypes = [...result.components.values()].find(c => c.name === 'mime-types');
      const mimeDb = [...result.components.values()].find(c => c.name === 'mime-db');

      const acceptsDeps = result.dependencyEdges.get(accepts.bomRef);
      assert.ok(acceptsDeps.has(mimeTypes.bomRef), 'accepts should depend on mime-types');

      const mimeTypesDeps = result.dependencyEdges.get(mimeTypes.bomRef);
      assert.ok(mimeTypesDeps.has(mimeDb.bomRef), 'mime-types should depend on mime-db');
    });

    it('preserves dependency chain: accepts → negotiator', () => {
      const result = resolveFixture('transitive-project');

      const accepts = [...result.components.values()].find(c => c.name === 'accepts');
      const negotiator = [...result.components.values()].find(c => c.name === 'negotiator');

      const acceptsDeps = result.dependencyEdges.get(accepts.bomRef);
      assert.ok(acceptsDeps.has(negotiator.bomRef), 'accepts should depend on negotiator');
    });
  });

  describe('mixed-dependencies-project', () => {
    it('includes all dependency groups', () => {
      const result = resolveFixture('mixed-dependencies-project');

      const ms = [...result.components.values()].find(c => c.name === 'ms' && c.version === '2.1.3');
      assert.ok(ms, 'ms should be found');
      assert.equal(ms.dependencyType, 'direct');
      assert.ok(ms.dependencyGroups.includes('dependencies'));

      const isOdd = [...result.components.values()].find(c => c.name === 'is-odd');
      assert.ok(isOdd, 'is-odd should be found (dev dependency)');
      assert.equal(isOdd.dependencyType, 'direct');
      assert.ok(isOdd.dependencyGroups.includes('devDependencies'));

      const colorName = [...result.components.values()].find(c => c.name === 'color-name');
      assert.ok(colorName, 'color-name should be found (optional dependency)');
      assert.equal(colorName.dependencyType, 'direct');
      assert.ok(colorName.dependencyGroups.includes('optionalDependencies'));
    });

    it('includes resolved peer dependencies', () => {
      const result = resolveFixture('mixed-dependencies-project');

      const debug = [...result.components.values()].find(c => c.name === 'debug');
      assert.ok(debug, 'debug should be found (peer dependency)');
      assert.equal(debug.dependencyType, 'direct');
      assert.ok(debug.dependencyGroups.includes('peerDependencies'));
    });

    it('does not exclude dev dependencies', () => {
      const result = resolveFixture('mixed-dependencies-project');

      const isNumber = [...result.components.values()].find(c => c.name === 'is-number');
      assert.ok(isNumber, 'is-number (transitive of dev dep is-odd) should be included');
    });
  });

  describe('multiple-versions-project', () => {
    it('retains both versions of the same package', () => {
      const result = resolveFixture('multiple-versions-project');

      const sharedDeps = [...result.components.values()].filter(c => c.name === 'shared-dep');
      assert.equal(sharedDeps.length, 2, 'Should have 2 versions of shared-dep');

      const versions = sharedDeps.map(c => c.version).sort();
      assert.deepEqual(versions, ['1.5.0', '2.0.0']);
    });

    it('maintains correct edges for different versions', () => {
      const result = resolveFixture('multiple-versions-project');

      const parentA = [...result.components.values()].find(c => c.name === 'foo-parent-a');
      const parentB = [...result.components.values()].find(c => c.name === 'foo-parent-b');
      const shared150 = [...result.components.values()].find(c => c.name === 'shared-dep' && c.version === '1.5.0');
      const shared200 = [...result.components.values()].find(c => c.name === 'shared-dep' && c.version === '2.0.0');

      const parentADeps = result.dependencyEdges.get(parentA.bomRef);
      assert.ok(parentADeps.has(shared150.bomRef), 'foo-parent-a should depend on shared-dep@1.5.0');

      const parentBDeps = result.dependencyEdges.get(parentB.bomRef);
      assert.ok(parentBDeps.has(shared200.bomRef), 'foo-parent-b should depend on shared-dep@2.0.0');
    });
  });

  describe('scoped-package-project', () => {
    it('handles scoped packages correctly', () => {
      const result = resolveFixture('scoped-package-project');

      const babelCore = [...result.components.values()].find(c => c.name === '@babel/core');
      assert.ok(babelCore, '@babel/core should be found');
      assert.equal(babelCore.version, '7.24.0');
      assert.equal(babelCore.dependencyType, 'direct');
    });

    it('generates correct Package URLs for scoped packages', () => {
      const result = resolveFixture('scoped-package-project');

      const babelCore = [...result.components.values()].find(c => c.name === '@babel/core');
      assert.equal(babelCore.purl, 'pkg:npm/%40babel/core@7.24.0');

      const typesNode = [...result.components.values()].find(c => c.name === '@types/node');
      assert.equal(typesNode.purl, 'pkg:npm/%40types/node@20.11.0');
    });
  });

  describe('no-node-modules-project', () => {
    it('resolves all dependencies from lockfile without node_modules', () => {
      const result = resolveFixture('no-node-modules-project');

      // Root + ms + is-odd + is-number = 4
      assert.equal(result.components.size, 4, 'Should discover all packages from lockfile');

      const ms = [...result.components.values()].find(c => c.name === 'ms');
      assert.ok(ms);
      assert.equal(ms.version, '2.1.3');
    });
  });

  describe('unresolved-deps-project', () => {
    it('generates warnings for unresolved dependencies', () => {
      const result = resolveFixture('unresolved-deps-project');

      const unresolvedWarnings = result.warnings.filter(w => w.code === 'UNRESOLVED_DEPENDENCY');
      assert.ok(unresolvedWarnings.length > 0, 'Should have unresolved dependency warnings');

      const nonexistentWarning = unresolvedWarnings.find(w => w.dependency === 'nonexistent-package');
      assert.ok(nonexistentWarning, 'Should warn about nonexistent-package');
    });

    it('still resolves other valid dependencies', () => {
      const result = resolveFixture('unresolved-deps-project');

      const ms = [...result.components.values()].find(c => c.name === 'ms');
      assert.ok(ms, 'ms should still be resolved');
      assert.equal(ms.version, '2.1.3');
    });
  });

  describe('manifest-only resolution', () => {
    it('creates partial results with version ranges instead of resolved versions', () => {
      const pkgResult = parsePackageJson(path.join(fixturesDir, 'missing-lockfile-project', 'package.json'));
      assert.equal(pkgResult.errors.length, 0);

      const result = resolveManifestOnly(pkgResult.data);

      // Root + express + jest = 3
      assert.equal(result.components.size, 3);

      const express = [...result.components.values()].find(c => c.name === 'express');
      assert.ok(express);
      assert.equal(express.version, null, 'Version should be null (unresolved)');
      assert.equal(express.versionRange, '^4.18.0');
      assert.equal(express.dependencyType, 'direct');
      assert.ok(express.dependencyGroups.includes('dependencies'));
      assert.equal(express.resolved, null, 'resolved should be null for manifest-only partial scans');
      assert.equal(express.integrity, null, 'integrity should be null for manifest-only partial scans');
      assert.ok(Array.isArray(express.installPaths), 'installPaths should be an array');
      assert.equal(express.installPaths.length, 0);

      const jest = [...result.components.values()].find(c => c.name === 'jest');
      assert.ok(jest);
      assert.ok(jest.dependencyGroups.includes('devDependencies'));
    });
  });

  describe('nested conflicting versions with root declaration', () => {
    it('correctly classifies nested conflicting package as transitive when root declares a direct dependency with same name', () => {
      const mockPkgJson = {
        name: 'test-app',
        version: '1.0.0',
        dependencies: {
          'foo-parent': '1.0.0',
          'shared-pkg': '2.0.0',
        },
      };

      const mockLockfile = {
        packages: {
          '': { name: 'test-app', version: '1.0.0' },
          'node_modules/foo-parent': {
            version: '1.0.0',
            dependencies: { 'shared-pkg': '1.0.0' },
          },
          'node_modules/foo-parent/node_modules/shared-pkg': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/shared-pkg/-/shared-pkg-1.0.0.tgz',
          },
          'node_modules/shared-pkg': {
            version: '2.0.0',
            resolved: 'https://registry.npmjs.org/shared-pkg/-/shared-pkg-2.0.0.tgz',
          },
        },
      };

      const result = resolveDependencies(mockPkgJson, mockLockfile);

      // Root + foo-parent + shared-pkg@2.0.0 + shared-pkg@1.0.0 = 4 components
      assert.equal(result.components.size, 4);

      const sharedDirect = [...result.components.values()].find(c => c.name === 'shared-pkg' && c.version === '2.0.0');
      assert.ok(sharedDirect);
      assert.equal(sharedDirect.dependencyType, 'direct', 'Root declared version 2.0.0 should be direct');
      assert.deepEqual(sharedDirect.dependencyGroups, ['dependencies']);

      const sharedTransitive = [...result.components.values()].find(c => c.name === 'shared-pkg' && c.version === '1.0.0');
      assert.ok(sharedTransitive);
      assert.equal(sharedTransitive.dependencyType, 'transitive', 'Nested conflicting version 1.0.0 should be transitive');
      assert.deepEqual(sharedTransitive.dependencyGroups, []);
    });
  });

  describe('zero-dependency project', () => {
    it('handles projects with empty dependency lists cleanly', () => {
      const mockPkgJson = {
        name: 'zero-dep-app',
        version: '1.0.0',
        dependencies: {},
      };

      const mockLockfile = {
        packages: {
          '': { name: 'zero-dep-app', version: '1.0.0' },
        },
      };

      const result = resolveDependencies(mockPkgJson, mockLockfile);

      assert.equal(result.components.size, 1, 'Only root component should exist');
      const root = [...result.components.values()][0];
      assert.equal(root.name, 'zero-dep-app');
      assert.equal(root.isRoot, true);
      assert.equal(result.dependencyEdges.get(result.rootRef).size, 0, 'Root edges should be empty');
      assert.equal(result.warnings.length, 0);
    });
  });
});
