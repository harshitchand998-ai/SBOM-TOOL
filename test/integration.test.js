import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { scanProject, scanProjectSync } from '../src/scanner/index.js';
import { validateStructure } from '../src/validator.js';
import { ErrorCodes, ScanStatus } from '../src/errors.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('Order 7: Dependency Graph and First-Party Discovery Integration', () => {

  // Scenario 1: Normal npm project without workspaces
  it('1. Normal npm project without workspaces: scans complete with root and third-party classification', async () => {
    const fixturePath = path.join(fixturesDir, 'simple-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.errors.length, 0);

    const rootComp = result.components.find(c => c.isRoot);
    assert.ok(rootComp, 'Root component must exist');
    assert.equal(rootComp.isFirstParty, true);
    assert.equal(rootComp.classification, 'first-party');
    assert.equal(rootComp.origin, 'first-party');

    const thirdParty = result.components.filter(c => !c.isRoot);
    assert.ok(thirdParty.length > 0);
    for (const comp of thirdParty) {
      assert.equal(comp.isFirstParty, false);
      assert.equal(comp.classification, 'third-party');
      assert.equal(comp.origin, 'third-party');
    }

    // Verify edge integrity
    const allBomRefs = new Set(result.components.map(c => c.bomRef));
    for (const [parentRef, childRefs] of Object.entries(result.dependencyEdges)) {
      assert.ok(allBomRefs.has(parentRef), `Parent edge ${parentRef} must exist in components`);
      for (const childRef of childRefs) {
        assert.ok(allBomRefs.has(childRef), `Child edge ${childRef} must exist in components`);
      }
    }
  });

  // Scenario 2: Root project with one workspace
  it('2. Root project with one workspace: discovers single workspace component', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-simple-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.PARTIAL); // No lockfile in simple workspace fixture
    const root = result.components.find(c => c.isRoot);
    assert.ok(root);
    assert.equal(root.isFirstParty, true);

    const ws = result.components.find(c => c.dependencyType === 'workspace');
    assert.ok(ws, 'Workspace package pkg-a must be present');
    assert.equal(ws.name, 'pkg-a');
    assert.equal(ws.isFirstParty, true);
    assert.equal(ws.classification, 'first-party');
  });

  // Scenario 3: Root project with multiple workspaces
  it('3. Root project with multiple workspaces: discovers all workspaces with lockfile v3', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.errors.length, 0);

    const workspaces = result.components.filter(c => c.dependencyType === 'workspace');
    assert.equal(workspaces.length, 2);
    const names = workspaces.map(w => w.name).sort();
    assert.deepEqual(names, ['pkg-a', 'pkg-b']);

    // Check CycloneDX BOM
    assert.ok(result.bom);
    const validation = validateStructure(result.bom);
    assert.ok(validation.valid, `BOM validation errors: ${validation.errors.join(', ')}`);
  });

  // Scenario 4: Nested workspace packages
  it('4. Nested workspace packages: discovers packages matching deep wildcards', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-nested-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'modules', 'core', 'utils'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'nested-monorepo',
          version: '1.0.0',
          workspaces: ['modules/**/*'],
        })
      );
      fs.writeFileSync(
        path.join(tmpDir, 'modules', 'core', 'utils', 'package.json'),
        JSON.stringify({
          name: '@deep/utils',
          version: '0.5.0',
        })
      );

      const result = await scanProject(tmpDir);
      const ws = result.components.find(c => c.name === '@deep/utils');
      assert.ok(ws, 'Nested workspace package must be discovered');
      assert.equal(ws.isFirstParty, true);
      assert.equal(ws.classification, 'first-party');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 5: Workspace dependency chains
  it('5. Workspace dependency chains: creates edges root -> pkg-a -> pkg-b', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    const root = result.components.find(c => c.isRoot);
    const pkgA = result.components.find(c => c.name === 'pkg-a');
    const pkgB = result.components.find(c => c.name === 'pkg-b');

    assert.ok(result.dependencyEdges[root.bomRef].includes(pkgA.bomRef), 'Root must depend on pkg-a');
    assert.ok(result.dependencyEdges[pkgA.bomRef].includes(pkgB.bomRef), 'pkg-a must depend on pkg-b');
  });

  // Scenario 6: Workspace package depending on a third-party package
  it('6. Workspace package depending on a third-party package: creates edge pkg-a -> is-odd', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    const pkgA = result.components.find(c => c.name === 'pkg-a');
    const isOdd = result.components.find(c => c.name === 'is-odd');

    assert.ok(isOdd, 'is-odd must exist in components');
    assert.equal(isOdd.isFirstParty, false);
    assert.equal(isOdd.classification, 'third-party');
    assert.ok(result.dependencyEdges[pkgA.bomRef].includes(isOdd.bomRef), 'pkg-a must depend on is-odd');
  });

  // Scenario 7: Third-party package depending on another third-party package
  it('7. Third-party package depending on another third-party package: creates edge is-odd -> is-number', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    const isOdd = result.components.find(c => c.name === 'is-odd');
    const isNumberV6 = result.components.find(c => c.name === 'is-number' && c.version === '6.0.0');

    assert.ok(isNumberV6, 'is-number v6.0.0 must exist');
    assert.ok(result.dependencyEdges[isOdd.bomRef].includes(isNumberV6.bomRef), 'is-odd must depend on is-number v6');
  });

  // Scenario 8: Multiple installed versions of the same third-party package
  it('8. Multiple installed versions of the same third-party package: retains both versions with distinct edges', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    const isNumberComps = result.components.filter(c => c.name === 'is-number');
    assert.equal(isNumberComps.length, 2, 'Must have 2 distinct is-number components');

    const v6 = isNumberComps.find(c => c.version === '6.0.0');
    const v7 = isNumberComps.find(c => c.version === '7.0.0');
    assert.ok(v6 && v7);

    const pkgB = result.components.find(c => c.name === 'pkg-b');
    const isOdd = result.components.find(c => c.name === 'is-odd');

    assert.ok(result.dependencyEdges[pkgB.bomRef].includes(v7.bomRef), 'pkg-b must depend on is-number v7');
    assert.ok(result.dependencyEdges[isOdd.bomRef].includes(v6.bomRef), 'is-odd must depend on is-number v6');
  });

  // Scenario 9: Workspace dependency with compatible version
  it('9. Workspace dependency with compatible version: links correctly', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    const pkgA = result.components.find(c => c.name === 'pkg-a');
    const pkgB = result.components.find(c => c.name === 'pkg-b');

    assert.ok(result.dependencyEdges[pkgA.bomRef].includes(pkgB.bomRef));
  });

  // Scenario 10: Workspace dependency with incompatible version
  it('10. Workspace dependency with incompatible version: emits warning and does not create edge', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-incompatible-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'client'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'packages', 'service'), { recursive: true });

      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'incompatible-monorepo',
          version: '1.0.0',
          workspaces: ['packages/*'],
        })
      );

      // Client requires service ^2.0.0, but service is 1.0.0
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'client', 'package.json'),
        JSON.stringify({
          name: 'client',
          version: '1.0.0',
          dependencies: { service: '^2.0.0' },
        })
      );

      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'service', 'package.json'),
        JSON.stringify({
          name: 'service',
          version: '1.0.0',
        })
      );

      const result = await scanProject(tmpDir);
      const client = result.components.find(c => c.name === 'client');
      const service = result.components.find(c => c.name === 'service');

      assert.ok(client && service);
      // Must not link
      assert.ok(!result.dependencyEdges[client.bomRef].includes(service.bomRef), 'Incompatible workspace must not be linked');
      // Must emit UNRESOLVED_DEPENDENCY warning
      assert.ok(
        result.warnings.some(
          w => w.code === ErrorCodes.UNRESOLVED_DEPENDENCY && w.message.includes('incompatible')
        ),
        'Must emit warning for incompatible version'
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 11: Workspace dependency absent from the lockfile
  it('11. Workspace dependency absent from the lockfile: warns and does not invent edge', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-absent-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-a'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-b'), { recursive: true });

      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'absent-monorepo',
          version: '1.0.0',
          workspaces: ['packages/*'],
        })
      );

      // pkg-a declares dep on non-existent pkg-c
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'pkg-a', 'package.json'),
        JSON.stringify({
          name: 'pkg-a',
          version: '1.0.0',
          dependencies: { 'pkg-c': '^1.0.0' },
        })
      );

      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'pkg-b', 'package.json'),
        JSON.stringify({
          name: 'pkg-b',
          version: '1.0.0',
        })
      );

      // Lockfile has no entry for pkg-c
      fs.writeFileSync(
        path.join(tmpDir, 'package-lock.json'),
        JSON.stringify({
          name: 'absent-monorepo',
          version: '1.0.0',
          lockfileVersion: 3,
          requires: true,
          packages: {
            '': { name: 'absent-monorepo', version: '1.0.0', workspaces: ['packages/pkg-a', 'packages/pkg-b'] },
            'node_modules/pkg-a': { resolved: 'packages/pkg-a', link: true },
            'node_modules/pkg-b': { resolved: 'packages/pkg-b', link: true },
            'packages/pkg-a': { version: '1.0.0', dependencies: { 'pkg-c': '^1.0.0' } },
            'packages/pkg-b': { version: '1.0.0' },
          },
        })
      );

      const result = await scanProject(tmpDir);
      assert.ok(
        result.warnings.some(
          w => w.code === ErrorCodes.UNRESOLVED_DEPENDENCY && (w.dependency === 'pkg-c' || w.message.includes('pkg-c'))
        ),
        'Must emit warning for dependency absent from lockfile'
      );

      const pkgA = result.components.find(c => c.name === 'pkg-a');
      assert.deepEqual(result.dependencyEdges[pkgA.bomRef], [], 'Must not invent edge for missing dependency');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 12: Workspace symlink entry with link: true
  it('12. Workspace symlink entry with link: true: resolves correctly without error', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.errors.length, 0);
    const pkgA = result.components.find(c => c.name === 'pkg-a');
    assert.ok(pkgA.installPaths.includes('node_modules/pkg-a'), 'installPaths must include link path');
  });

  // Scenario 13: Workspace package missing its manifest
  it('13. Workspace package missing its manifest: reports error and continues discovery of valid workspaces', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-missing-manifest-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'valid-pkg'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'packages', 'missing-manifest-pkg'), { recursive: true });

      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'missing-manifest-monorepo',
          version: '1.0.0',
          workspaces: ['packages/*'],
        })
      );

      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'valid-pkg', 'package.json'),
        JSON.stringify({
          name: 'valid-pkg',
          version: '1.0.0',
        })
      );
      // missing-manifest-pkg has NO package.json

      const result = await scanProject(tmpDir);
      assert.equal(result.status, ScanStatus.PARTIAL);
      assert.ok(
        result.errors.some(
          e => e.code === ErrorCodes.PACKAGE_FILE_NOT_FOUND && e.message.includes('missing-manifest-pkg')
        )
      );

      const validPkg = result.components.find(c => c.name === 'valid-pkg');
      assert.ok(validPkg, 'Valid package must still be discovered');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 14: Duplicate workspace package names
  it('14. Duplicate workspace package names: reports layout error and maintains unambiguous bomRefs', async () => {
    const fixturePath = path.join(fixturesDir, 'workspace-duplicate-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.PARTIAL);
    assert.ok(
      result.errors.some(
        e => e.code === ErrorCodes.UNSUPPORTED_WORKSPACE_LAYOUT && e.message.includes('Duplicate workspace package name')
      )
    );

    const dupes = result.components.filter(c => c.name === 'duplicate-pkg');
    assert.equal(dupes.length, 2);
    assert.notEqual(dupes[0].bomRef, dupes[1].bomRef, 'bomRefs must be unique');
  });

  // Scenario 15: Root package name collision
  it('15. Root package name collision: disambiguates identifiers safely', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-collision-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'core'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'same-name-project',
          version: '1.0.0',
          workspaces: ['packages/*'],
        })
      );
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'core', 'package.json'),
        JSON.stringify({
          name: 'same-name-project',
          version: '1.0.0',
        })
      );

      const result = await scanProject(tmpDir);
      const root = result.components.find(c => c.isRoot);
      const ws = result.components.find(c => !c.isRoot && c.name === 'same-name-project');

      assert.ok(root && ws);
      assert.notEqual(root.bomRef, ws.bomRef, 'Root and workspace bomRefs must be distinct');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 16: Glob pattern packages/**/client
  it('16. Glob pattern packages/**/client: matches only client and does not match intermediate directories', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-glob-intermediate-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'service'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'service', 'package.json'),
        JSON.stringify({ name: 'service', version: '1.0.0' })
      );
      fs.mkdirSync(path.join(tmpDir, 'packages', 'sub', 'client'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'sub', 'client', 'package.json'),
        JSON.stringify({ name: 'client', version: '1.0.0' })
      );
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'glob-root',
          version: '1.0.0',
          workspaces: ['packages/**/client'],
        })
      );

      const result = await scanProject(tmpDir);
      const wsNames = result.components.filter(c => !c.isRoot).map(c => c.name);
      assert.deepEqual(wsNames, ['client']);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 17: Windows-style workspace pattern
  it('17. Windows-style workspace pattern: handles backslash path patterns', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-backslash-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'win-pkg'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'win-pkg', 'package.json'),
        JSON.stringify({ name: 'win-pkg', version: '1.0.0' })
      );
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'win-root',
          version: '1.0.0',
          workspaces: ['packages\\*'],
        })
      );

      const result = await scanProject(tmpDir);
      const ws = result.components.find(c => c.name === 'win-pkg');
      assert.ok(ws, 'win-pkg must be discovered despite backslash pattern');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 18: Negated workspace patterns
  it('18. Negated workspace patterns: excludes negated directories', async () => {
    const tmpDir = path.join(os.tmpdir(), `test-ws-negation-${Date.now()}`);
    try {
      fs.mkdirSync(path.join(tmpDir, 'packages', 'included-pkg'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'included-pkg', 'package.json'),
        JSON.stringify({ name: 'included-pkg', version: '1.0.0' })
      );
      fs.mkdirSync(path.join(tmpDir, 'packages', 'excluded-pkg'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'packages', 'excluded-pkg', 'package.json'),
        JSON.stringify({ name: 'excluded-pkg', version: '1.0.0' })
      );
      fs.writeFileSync(
        path.join(tmpDir, 'package.json'),
        JSON.stringify({
          name: 'negation-root',
          version: '1.0.0',
          workspaces: ['packages/*', '!packages/excluded-pkg'],
        })
      );

      const result = await scanProject(tmpDir);
      const wsNames = result.components.filter(c => !c.isRoot).map(c => c.name);
      assert.deepEqual(wsNames, ['included-pkg']);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Scenario 19: Unresolved third-party dependency
  it('19. Unresolved third-party dependency: emits UNRESOLVED_DEPENDENCY warning', async () => {
    const fixturePath = path.join(fixturesDir, 'unresolved-deps-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.ok(
      result.warnings.some(
        w => w.code === ErrorCodes.UNRESOLVED_DEPENDENCY && (w.dependency === 'nonexistent-package' || w.message.includes('nonexistent-package'))
      )
    );
  });

  // Scenario 20: Zero-dependency project
  it('20. Zero-dependency project: returns root component only with empty edges', async () => {
    const fixturePath = path.join(fixturesDir, 'zero-deps-project');
    const result = await scanProject(fixturePath);

    assert.equal(result.status, ScanStatus.COMPLETE);
    assert.equal(result.components.length, 1);
    assert.equal(result.components[0].isRoot, true);
    assert.equal(result.components[0].name, 'zero-deps-project');
    assert.deepEqual(result.dependencyEdges[result.components[0].bomRef], []);
  });

  // Edge integrity across all fixtures
  it('Edge integrity: every edge in dependencyEdges references an existing component bomRef', async () => {
    const fixtureNames = [
      'simple-project',
      'transitive-project',
      'mixed-dependencies-project',
      'multiple-versions-project',
      'scoped-package-project',
      'workspace-with-lockfile-project',
      'workspace-multi-project',
      'workspace-simple-project',
      'zero-deps-project',
    ];

    for (const fixtureName of fixtureNames) {
      const fixturePath = path.join(fixturesDir, fixtureName);
      const result = await scanProject(fixturePath);
      const allBomRefs = new Set(result.components.map(c => c.bomRef));

      for (const [parentRef, childRefs] of Object.entries(result.dependencyEdges)) {
        assert.ok(allBomRefs.has(parentRef), `Fixture ${fixtureName}: parent edge ${parentRef} must exist in components`);
        for (const childRef of childRefs) {
          assert.ok(allBomRefs.has(childRef), `Fixture ${fixtureName}: child edge ${childRef} must exist in components`);
        }
      }
    }
  });

  // Sync and Async API Parity
  it('Sync and Async scanner API parity: produces identical output between scanProject and scanProjectSync', async () => {
    const fixtureNames = [
      'simple-project',
      'workspace-with-lockfile-project',
      'workspace-multi-project',
      'workspace-simple-project',
      'zero-deps-project',
    ];

    for (const fixtureName of fixtureNames) {
      const fixturePath = path.join(fixturesDir, fixtureName);
      const syncResult = scanProjectSync(fixturePath);
      const asyncResult = await scanProject(fixturePath);

      // Compare non-dynamic fields
      assert.equal(syncResult.status, asyncResult.status);
      assert.equal(syncResult.projectPath, asyncResult.projectPath);
      assert.deepEqual(syncResult.projectMetadata, asyncResult.projectMetadata);
      assert.equal(syncResult.lockfileVersion, asyncResult.lockfileVersion);
      assert.deepEqual(syncResult.errors, asyncResult.errors);
      assert.deepEqual(syncResult.warnings, asyncResult.warnings);
      assert.deepEqual(syncResult.components, asyncResult.components);
      assert.deepEqual(syncResult.dependencyEdges, asyncResult.dependencyEdges);

      if (syncResult.bom && asyncResult.bom) {
        assert.equal(syncResult.bom.components.length, asyncResult.bom.components.length);
        assert.equal(syncResult.bom.dependencies.length, asyncResult.bom.dependencies.length);
      }
    }
  });
});
