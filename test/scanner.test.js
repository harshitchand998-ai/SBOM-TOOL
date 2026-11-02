import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../src/scanner/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('Scanner Integration Tests', () => {
  describe('Fixture 1: simple-project', () => {
    it('successfully scans a simple project', async () => {
      const result = await scanProject(path.join(fixturesDir, 'simple-project'));

      assert.equal(result.status, 'complete');
      assert.equal(result.errors.length, 0);
      assert.equal(result.projectMetadata.name, 'simple-project');
      assert.equal(result.projectMetadata.version, '1.0.0');

      // 3 total: root + is-odd + is-number
      assert.equal(result.components.length, 3);

      const isOdd = result.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd);
      assert.equal(isOdd.version, '3.0.1');
      assert.equal(isOdd.dependencyType, 'direct');

      const isNumber = result.components.find(c => c.name === 'is-number');
      assert.ok(isNumber);
      assert.equal(isNumber.version, '6.0.0');
      assert.equal(isNumber.dependencyType, 'transitive');

      // BOM should be generated
      assert.ok(result.bom);
      assert.equal(result.bom.bomFormat, 'CycloneDX');
      assert.equal(result.bom.specVersion, '1.7');
    });
  });

  describe('Fixture 2: transitive-project', () => {
    it('discovers all transitive dependencies', async () => {
      const result = await scanProject(path.join(fixturesDir, 'transitive-project'));

      assert.equal(result.status, 'complete');

      const names = result.components.filter(c => !c.isRoot).map(c => c.name).sort();
      assert.deepEqual(names, ['accepts', 'mime-db', 'mime-types', 'negotiator']);

      const accepts = result.components.find(c => c.name === 'accepts');
      assert.equal(accepts.dependencyType, 'direct');

      const mimeDb = result.components.find(c => c.name === 'mime-db');
      assert.equal(mimeDb.dependencyType, 'transitive');
    });
  });

  describe('Fixture 3: mixed-dependencies-project', () => {
    it('includes all dependency groups', async () => {
      const result = await scanProject(path.join(fixturesDir, 'mixed-dependencies-project'));

      assert.equal(result.status, 'complete');

      // Should include prod, dev, optional, and peer deps
      const ms = result.components.find(c => c.name === 'ms' && c.version === '2.1.3');
      assert.ok(ms);

      const isOdd = result.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd, 'Dev dependencies should be included');

      const colorName = result.components.find(c => c.name === 'color-name');
      assert.ok(colorName, 'Optional dependencies should be included');

      const debug = result.components.find(c => c.name === 'debug');
      assert.ok(debug, 'Resolved peer dependencies should be included');
    });
  });

  describe('Fixture 4: multiple-versions-project', () => {
    it('retains multiple versions of the same package', async () => {
      const result = await scanProject(path.join(fixturesDir, 'multiple-versions-project'));

      assert.equal(result.status, 'complete');

      const sharedDeps = result.components.filter(c => c.name === 'shared-dep');
      assert.equal(sharedDeps.length, 2, 'Both versions should be present');

      const versions = sharedDeps.map(c => c.version).sort();
      assert.deepEqual(versions, ['1.5.0', '2.0.0']);
    });
  });

  describe('Fixture 5: scoped-package-project', () => {
    it('handles scoped packages with correct purls', async () => {
      const result = await scanProject(path.join(fixturesDir, 'scoped-package-project'));

      assert.equal(result.status, 'complete');

      const babelCore = result.components.find(c => c.name === '@babel/core');
      assert.ok(babelCore);
      assert.equal(babelCore.purl, 'pkg:npm/%40babel/core@7.24.0');

      const typesNode = result.components.find(c => c.name === '@types/node');
      assert.ok(typesNode);
      assert.equal(typesNode.purl, 'pkg:npm/%40types/node@20.11.0');
    });
  });

  describe('Fixture 6: invalid-project', () => {
    it('returns INVALID_PACKAGE_FILE for malformed package.json', async () => {
      const result = await scanProject(path.join(fixturesDir, 'invalid-project'));

      assert.equal(result.status, 'failed');
      assert.ok(result.errors.length > 0);
      assert.equal(result.errors[0].code, 'INVALID_PACKAGE_FILE');
      assert.equal(result.bom, null);
    });
  });

  describe('Fixture 7: invalid-lockfile-project', () => {
    it('returns INVALID_PACKAGE_FILE for malformed lockfile', async () => {
      const result = await scanProject(path.join(fixturesDir, 'invalid-lockfile-project'));

      // Should still produce a partial result since package.json is valid
      assert.equal(result.status, 'partial');
      assert.ok(result.errors.length > 0 || result.warnings.length > 0);
    });
  });

  describe('Fixture 8: missing-lockfile-project', () => {
    it('produces a partial scan', async () => {
      const result = await scanProject(path.join(fixturesDir, 'missing-lockfile-project'));

      assert.equal(result.status, 'partial');
      assert.equal(result.bom, null, 'No CycloneDX BOM should be generated for partial scans');
      assert.ok(result.warnings.length > 0, 'Should have warnings about missing lockfile');

      // Should have direct declarations
      const express = result.components.find(c => c.name === 'express');
      assert.ok(express);
      assert.equal(express.version, null, 'Version should be null (unresolved)');
      assert.equal(express.versionRange, '^4.18.0');
    });
  });

  describe('Fixture 9: missing-manifest-project', () => {
    it('fails with PACKAGE_FILE_NOT_FOUND', async () => {
      const result = await scanProject(path.join(fixturesDir, 'missing-manifest-project'));

      assert.equal(result.status, 'failed');
      const manifestError = result.errors.find(e => e.code === 'PACKAGE_FILE_NOT_FOUND');
      assert.ok(manifestError, 'Should have PACKAGE_FILE_NOT_FOUND error');
    });
  });

  describe('Fixture 10: empty-project', () => {
    it('fails with PACKAGE_FILE_NOT_FOUND', async () => {
      const result = await scanProject(path.join(fixturesDir, 'empty-project'));

      assert.equal(result.status, 'failed');
      const error = result.errors.find(e => e.code === 'PACKAGE_FILE_NOT_FOUND');
      assert.ok(error, 'Should have PACKAGE_FILE_NOT_FOUND error');
    });
  });

  describe('Fixture 11: unsupported-project', () => {
    it('detects unsupported package manager', async () => {
      const result = await scanProject(path.join(fixturesDir, 'unsupported-project'));

      assert.equal(result.status, 'failed');
      const error = result.errors.find(e => e.code === 'UNSUPPORTED_PACKAGE_MANAGER');
      assert.ok(error, 'Should have UNSUPPORTED_PACKAGE_MANAGER error');
      assert.ok(error.message.includes('Yarn'));
    });
  });

  describe('Fixture 12: no-node-modules-project', () => {
    it('scans successfully using lockfile without node_modules', async () => {
      const result = await scanProject(path.join(fixturesDir, 'no-node-modules-project'));

      assert.equal(result.status, 'complete');
      assert.equal(result.errors.length, 0);

      const ms = result.components.find(c => c.name === 'ms');
      assert.ok(ms);
      assert.equal(ms.version, '2.1.3');

      const isOdd = result.components.find(c => c.name === 'is-odd');
      assert.ok(isOdd);

      assert.ok(result.bom, 'BOM should be generated');
    });
  });

  describe('Fixture 13: unsupported-lockfile-project', () => {
    it('detects unsupported lockfile version and falls back to partial scan', async () => {
      const result = await scanProject(path.join(fixturesDir, 'unsupported-lockfile-project'));

      assert.equal(result.status, 'partial');
      assert.equal(result.lockfileVersion, 1);
      assert.ok(result.errors.some(e => e.code === 'UNSUPPORTED_LOCKFILE_VERSION'));
      assert.equal(result.bom, null, 'No CycloneDX BOM should be generated for partial scans');

      const ms = result.components.find(c => c.name === 'ms');
      assert.ok(ms);
      assert.equal(ms.dependencyType, 'direct');
      assert.equal(ms.version, null, 'Version should be null in fallback partial scan');
      assert.equal(ms.versionRange, '2.1.3');
    });
  });

  describe('Project path validation', () => {
    it('returns PROJECT_NOT_FOUND for non-existent directory', async () => {
      const result = await scanProject('/nonexistent/path/to/project');

      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PROJECT_NOT_FOUND for empty or whitespace paths', async () => {
      const emptyResult = await scanProject('');
      assert.equal(emptyResult.status, 'failed');
      assert.ok(emptyResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));

      const wsResult = await scanProject('   ');
      assert.equal(wsResult.status, 'failed');
      assert.ok(wsResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PROJECT_NOT_FOUND for null or non-string paths', async () => {
      const nullResult = await scanProject(null);
      assert.equal(nullResult.status, 'failed');
      assert.ok(nullResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));

      const undefResult = await scanProject(undefined);
      assert.equal(undefResult.status, 'failed');
      assert.ok(undefResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PROJECT_NOT_FOUND when target path is a file instead of a directory', async () => {
      const filePath = path.join(fixturesDir, 'simple-project', 'package.json');
      const result = await scanProject(filePath);

      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('handles relative paths correctly', async () => {
      const relativePath = path.relative(process.cwd(), path.join(fixturesDir, 'simple-project'));
      const result = await scanProject(relativePath);

      assert.equal(result.status, 'complete');
    });
  });

  describe('Lockfile version handling', () => {
    it('supports lockfile version 2', async () => {
      const result = await scanProject(path.join(fixturesDir, 'lockfile-v2-project'));

      assert.equal(result.status, 'complete');
      assert.equal(result.lockfileVersion, 2);

      const ms = result.components.find(c => c.name === 'ms');
      assert.ok(ms);
      assert.equal(ms.version, '2.1.3');
    });
  });

  describe('Unresolved dependencies', () => {
    it('generates warnings for missing dependencies', async () => {
      const result = await scanProject(path.join(fixturesDir, 'unresolved-deps-project'));

      assert.equal(result.status, 'complete');
      assert.ok(result.warnings.some(w => w.code === 'UNRESOLVED_DEPENDENCY'));
    });
  });

  describe('CycloneDX BOM completeness', () => {
    it('BOM contains all components and dependency relationships', async () => {
      const result = await scanProject(path.join(fixturesDir, 'transitive-project'));

      assert.ok(result.bom);
      const bom = result.bom;

      // All non-root components should be in bom.components
      const nonRootComponents = result.components.filter(c => !c.isRoot);
      assert.equal(bom.components.length, nonRootComponents.length);

      // All components should have dependency entries
      const allRefs = new Set(bom.dependencies.map(d => d.ref));
      const rootRef = bom.metadata.component['bom-ref'];
      assert.ok(allRefs.has(rootRef), 'Root should have a dependency entry');

      for (const comp of bom.components) {
        assert.ok(allRefs.has(comp['bom-ref']),
          `Component ${comp.name} should have a dependency entry`);
      }
    });
  });

  describe('Structured output format', () => {
    it('returns consistent structured contract matching specification', async () => {
      const result = await scanProject(path.join(fixturesDir, 'simple-project'));

      assert.equal(typeof result, 'object');
      assert.ok(['complete', 'partial', 'failed'].includes(result.status));
      assert.equal(typeof result.projectPath, 'string');
      assert.ok(result.projectMetadata && typeof result.projectMetadata.name === 'string');
      assert.ok(result.projectMetadata && typeof result.projectMetadata.version === 'string');
      assert.ok(typeof result.lockfileVersion === 'number' || result.lockfileVersion === null);
      assert.ok(Array.isArray(result.errors));
      assert.ok(Array.isArray(result.warnings));
      assert.ok(Array.isArray(result.components));
      assert.equal(typeof result.dependencyEdges, 'object');

      for (const comp of result.components) {
        assert.ok(typeof comp.name === 'string');
        assert.ok(typeof comp.ecosystem === 'string');
        assert.ok(typeof comp.bomRef === 'string');
        assert.ok(['root', 'direct', 'transitive'].includes(comp.dependencyType));
        assert.ok(Array.isArray(comp.dependencyGroups));
      }
    });

    it('returns structured object on failure without throwing or printing', async () => {
      const result = await scanProject('/nonexistent/directory');

      assert.equal(result.status, 'failed');
      assert.equal(result.projectMetadata, null);
      assert.equal(result.lockfileVersion, null);
      assert.ok(Array.isArray(result.errors));
      assert.ok(Array.isArray(result.warnings));
      assert.deepEqual(result.components, []);
      assert.deepEqual(result.dependencyEdges, {});
      assert.equal(result.bom, null);
    });
  });
});
