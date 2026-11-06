import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  discoverFirstPartyComponents,
  discoverFirstPartyComponentsSync,
  discoverWorkspaces,
  discoverWorkspacesSync,
  classifyComponent,
  classifyComponents,
  isVersionCompatible,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('First-Party Component & Workspace Discovery', () => {
  describe('Root application discovery', () => {
    it('discovers root application metadata as first-party component', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-simple-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'complete');
      assert.equal(result.errors.length, 0);
      assert.ok(result.root);
      assert.equal(result.root.name, 'workspace-simple-project');
      assert.equal(result.root.version, '1.0.0');
      assert.equal(result.root.description, 'Simple single workspace project');
      assert.equal(result.root.isFirstParty, true);
      assert.equal(result.root.classification, 'first-party');
      assert.equal(result.root.dependencyType, 'root');
      assert.equal(result.root.isRoot, true);
      assert.equal(result.root.location.relative, '.');
      assert.equal(result.root.location.resolved, path.resolve(targetPath));
      assert.deepEqual(result.root.workspaces, ['packages/*']);
    });
  });

  describe('No-workspace projects', () => {
    it('identifies root application with empty workspaces list when workspaces is not configured', async () => {
      const targetPath = path.join(fixturesDir, 'simple-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'complete');
      assert.equal(result.errors.length, 0);
      assert.ok(result.root);
      assert.equal(result.root.name, 'simple-project');
      assert.equal(result.root.isFirstParty, true);
      assert.equal(result.root.classification, 'first-party');
      assert.equal(result.root.workspaces, null);
      assert.deepEqual(result.workspaces, []);
      assert.equal(result.firstPartyComponents.length, 1);
      assert.equal(result.firstPartyComponents[0].name, 'simple-project');
      assert.deepEqual(result.workspaceDependencies, { 'simple-project': [] });
    });
  });

  describe('Single workspace & Array workspace configuration', () => {
    it('discovers single workspace package using array pattern format', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-simple-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'complete');
      assert.equal(result.workspaces.length, 1);

      const pkgA = result.workspaces.find(w => w.name === 'pkg-a');
      assert.ok(pkgA);
      assert.equal(pkgA.name, 'pkg-a');
      assert.equal(pkgA.version, '1.1.0');
      assert.equal(pkgA.description, 'Package A local workspace');
      assert.equal(pkgA.location.relative, 'packages/pkg-a');
      assert.equal(pkgA.isFirstParty, true);
      assert.equal(pkgA.classification, 'first-party');
      assert.equal(pkgA.dependencyType, 'workspace');
      assert.equal(pkgA.purl, 'pkg:npm/pkg-a@1.1.0');
      assert.equal(pkgA.bomRef, 'pkg:npm/pkg-a@1.1.0');

      // firstPartyComponents contains root + pkg-a
      assert.equal(result.firstPartyComponents.length, 2);
    });

    it('does not scan nested node_modules as a workspace package', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-simple-project');
      const result = await discoverFirstPartyComponents(targetPath);

      // Verify fake-pkg inside packages/pkg-a/node_modules/fake-pkg was ignored
      const fakePkg = result.workspaces.find(w => w.name === 'fake-pkg');
      assert.equal(fakePkg, undefined, 'node_modules must never be discovered as a workspace package');
    });
  });

  describe('Multiple workspaces & Object configuration & Scoped packages', () => {
    it('supports object workspaces configuration and discovers scoped workspace packages', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-multi-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'complete');
      assert.equal(result.errors.length, 0);

      // Discovers root + 3 packages = 4 first-party components
      assert.equal(result.workspaces.length, 3);
      assert.equal(result.firstPartyComponents.length, 4);

      // Verify scoped workspace package
      const sharedUtils = result.workspaces.find(w => w.name === '@company/shared-utils');
      assert.ok(sharedUtils);
      assert.equal(sharedUtils.version, '1.0.0');
      assert.equal(sharedUtils.description, 'Shared utility library');
      assert.equal(sharedUtils.location.relative, 'packages/shared-utils');
      assert.equal(sharedUtils.purl, 'pkg:npm/%40company/shared-utils@1.0.0');
      assert.equal(sharedUtils.bomRef, 'pkg:npm/%40company/shared-utils@1.0.0');
      assert.equal(sharedUtils.isFirstParty, true);

      // Verify authentication workspace
      const auth = result.workspaces.find(w => w.name === 'authentication');
      assert.ok(auth);
      assert.equal(auth.location.relative, 'packages/authentication');
      assert.equal(auth.isFirstParty, true);

      // Verify frontend workspace in apps/
      const frontend = result.workspaces.find(w => w.name === 'frontend');
      assert.ok(frontend);
      assert.equal(frontend.location.relative, 'apps/frontend');
      assert.equal(frontend.isFirstParty, true);
    });
  });

  describe('Workspace dependency relationships & semver matching', () => {
    it('identifies dependency relationships between discovered local workspaces', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-multi-project');
      const result = await discoverFirstPartyComponents(targetPath);

      // Relationship chain: frontend -> authentication -> @company/shared-utils
      const frontend = result.workspaces.find(w => w.name === 'frontend');
      assert.deepEqual(frontend.workspaceDependencies, ['authentication']);

      const auth = result.workspaces.find(w => w.name === 'authentication');
      assert.deepEqual(auth.workspaceDependencies, ['@company/shared-utils']);

      const sharedUtils = result.workspaces.find(w => w.name === '@company/shared-utils');
      assert.deepEqual(sharedUtils.workspaceDependencies, []);

      // Root depends on frontend
      assert.deepEqual(result.root.workspaceDependencies, ['frontend']);

      // Top-level workspaceDependencies adjacency list (by package name)
      assert.deepEqual(result.workspaceDependencies, {
        'workspace-multi-project': ['frontend'],
        frontend: ['authentication'],
        authentication: ['@company/shared-utils'],
        '@company/shared-utils': [],
      });

      // Top-level dependencyEdges adjacency list (by bomRef)
      assert.deepEqual(result.dependencyEdges, {
        'pkg:npm/workspace-multi-project@2.0.0': ['pkg:npm/frontend@1.0.0'],
        'pkg:npm/frontend@1.0.0': ['pkg:npm/authentication@1.0.0'],
        'pkg:npm/authentication@1.0.0': ['pkg:npm/%40company/shared-utils@1.0.0'],
        'pkg:npm/%40company/shared-utils@1.0.0': [],
      });
    });

    it('does not include external third-party dependencies in workspaceDependencies', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-multi-project');
      const result = await discoverFirstPartyComponents(targetPath);

      const frontend = result.workspaces.find(w => w.name === 'frontend');
      // frontend declares dependencies: { authentication: "^1.0.0", react: "^18.2.0" }
      assert.ok(frontend.dependencies.react);
      assert.ok(!frontend.workspaceDependencies.includes('react'));
      assert.ok(frontend.workspaceDependencies.includes('authentication'));
    });

    it('tests isVersionCompatible utility for various semver formats', () => {
      // Exact versions
      assert.equal(isVersionCompatible('1.0.0', '1.0.0'), true);
      assert.equal(isVersionCompatible('1.0.0', '2.0.0'), false);

      // Caret ranges
      assert.equal(isVersionCompatible('1.2.0', '^1.0.0'), true);
      assert.equal(isVersionCompatible('1.0.0', '^2.0.0'), false);
      assert.equal(isVersionCompatible('0.2.3', '^0.2.0'), true);
      assert.equal(isVersionCompatible('0.3.0', '^0.2.0'), false);

      // Tilde ranges
      assert.equal(isVersionCompatible('1.1.5', '~1.1.0'), true);
      assert.equal(isVersionCompatible('1.2.0', '~1.1.0'), false);

      // Wildcards & workspace protocols
      assert.equal(isVersionCompatible('1.0.0', '*'), true);
      assert.equal(isVersionCompatible('1.0.0', 'workspace:*'), true);
      assert.equal(isVersionCompatible('1.0.0', 'workspace:^1.0.0'), true);
      assert.equal(isVersionCompatible('1.0.0', 'workspace:^2.0.0'), false);

      // Comparison ranges
      assert.equal(isVersionCompatible('1.5.0', '>=1.0.0 <2.0.0'), true);
      assert.equal(isVersionCompatible('2.0.0', '>=1.0.0 <2.0.0'), false);
    });

    it('handles incompatible declared version range for workspace dependency', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-incompatible-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-consumer'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-provider'), { recursive: true });

        // Root manifest
        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'incompatible-range-project',
            version: '1.0.0',
            workspaces: ['packages/*'],
          })
        );

        // Consumer requires provider ^2.0.0
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-consumer', 'package.json'),
          JSON.stringify({
            name: 'pkg-consumer',
            version: '1.0.0',
            dependencies: {
              'pkg-provider': '^2.0.0',
            },
          })
        );

        // Provider is local version 1.0.0 (incompatible with ^2.0.0)
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-provider', 'package.json'),
          JSON.stringify({
            name: 'pkg-provider',
            version: '1.0.0',
          })
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);

        assert.equal(result.status, 'complete');
        const consumer = result.workspaces.find(w => w.name === 'pkg-consumer');
        assert.ok(consumer);

        // Incompatible version must NOT establish local workspace relationship
        assert.deepEqual(
          consumer.workspaceDependencies,
          [],
          'Incompatible version range must not establish workspace dependency'
        );

        // An UNRESOLVED_DEPENDENCY warning must be emitted
        assert.ok(
          result.warnings.some(
            w =>
              w.code === 'UNRESOLVED_DEPENDENCY' &&
              w.message.includes('incompatible with local workspace version')
          ),
          'Warning must be recorded for incompatible declared version range'
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('Third-party package classification & metadata verification', () => {
    it('correctly distinguishes first-party from third-party packages by name', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-multi-project');
      const result = await discoverFirstPartyComponents(targetPath);

      const firstPartyNames = new Set(result.firstPartyComponents.map(c => c.name));

      // Root component is first-party
      const rootComp = classifyComponent({ name: 'workspace-multi-project', isRoot: true }, firstPartyNames);
      assert.equal(rootComp.isFirstParty, true);
      assert.equal(rootComp.classification, 'first-party');

      // Local workspace is first-party
      const wsComp = classifyComponent({ name: '@company/shared-utils' }, firstPartyNames);
      assert.equal(wsComp.isFirstParty, true);
      assert.equal(wsComp.classification, 'first-party');

      // Package with SAME scope @company/ but NOT a local workspace must be third-party
      const scopedThirdParty = classifyComponent({ name: '@company/external-tool' }, firstPartyNames);
      assert.equal(scopedThirdParty.isFirstParty, false);
      assert.equal(scopedThirdParty.classification, 'third-party');

      // Regular npm packages must be third-party
      const reactComp = classifyComponent({ name: 'react' }, firstPartyNames);
      assert.equal(reactComp.isFirstParty, false);
      assert.equal(reactComp.classification, 'third-party');
    });

    it('does not rely solely on package names when installation-path or lockfile-link information is available', () => {
      const firstPartyContext = {
        names: new Set(['shared-utils', 'my-monorepo']),
        workspaces: [
          { name: 'shared-utils', version: '1.0.0', location: { relative: 'packages/shared-utils' } },
        ],
      };

      // 1. External registry tarball URL with matching workspace name -> MUST be classified as third-party
      const externalRegistryPkg = classifyComponent(
        {
          name: 'shared-utils',
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/shared-utils/-/shared-utils-1.0.0.tgz',
          installPaths: ['node_modules/shared-utils'],
        },
        firstPartyContext
      );
      assert.equal(
        externalRegistryPkg.isFirstParty,
        false,
        'External package instance with registry URL must not be classified as local workspace'
      );
      assert.equal(externalRegistryPkg.classification, 'third-party');

      // 2. Package instance with registry integrity in node_modules and not a link -> MUST be third-party
      const integrityPkg = classifyComponent(
        {
          name: 'shared-utils',
          version: '1.0.0',
          integrity: 'sha512-ABC123DEF==',
          installPaths: ['node_modules/shared-utils'],
          link: false,
        },
        firstPartyContext
      );
      assert.equal(
        integrityPkg.isFirstParty,
        false,
        'External package instance with registry integrity must be classified as third-party'
      );

      // 3. Package instance with explicit link: false installed in node_modules -> MUST be third-party
      const explicitNonLinkPkg = classifyComponent(
        {
          name: 'shared-utils',
          version: '1.0.0',
          link: false,
          installPaths: ['node_modules/shared-utils'],
        },
        firstPartyContext
      );
      assert.equal(
        explicitNonLinkPkg.isFirstParty,
        false,
        'Package instance with link: false installed in node_modules must be third-party'
      );

      // 4. Incompatible version installed in node_modules -> MUST be third-party
      const conflictingVersionPkg = classifyComponent(
        {
          name: 'shared-utils',
          version: '2.0.0',
          installPaths: ['node_modules/shared-utils'],
        },
        firstPartyContext
      );
      assert.equal(
        conflictingVersionPkg.isFirstParty,
        false,
        'Conflicting external version must be third-party'
      );

      // 5. Local workspace symlink with link: true -> MUST be first-party
      const localLinkPkg = classifyComponent(
        {
          name: 'shared-utils',
          version: '1.0.0',
          link: true,
          installPaths: ['node_modules/shared-utils'],
        },
        firstPartyContext
      );
      assert.equal(localLinkPkg.isFirstParty, true);
      assert.equal(localLinkPkg.classification, 'first-party');

      // 6. Local workspace component with dependencyType: workspace -> MUST be first-party
      const workspaceComp = classifyComponent(
        {
          name: 'shared-utils',
          version: '1.0.0',
          dependencyType: 'workspace',
          location: { relative: 'packages/shared-utils' },
        },
        firstPartyContext
      );
      assert.equal(workspaceComp.isFirstParty, true);
      assert.equal(workspaceComp.classification, 'first-party');
    });

    it('classifies component batches when options.components is provided', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-multi-project');
      const rawComponents = [
        { name: 'frontend', version: '1.0.0' },
        { name: '@company/shared-utils', version: '1.0.0' },
        { name: '@company/cloud-sdk', version: '3.0.0' },
        { name: 'react', version: '18.2.0' },
      ];

      const result = await discoverFirstPartyComponents(targetPath, { components: rawComponents });
      assert.ok(result.classifiedComponents);
      assert.equal(result.classifiedComponents.length, 4);

      const frontend = result.classifiedComponents.find(c => c.name === 'frontend');
      assert.equal(frontend.isFirstParty, true);
      assert.equal(frontend.classification, 'first-party');

      const sharedUtils = result.classifiedComponents.find(c => c.name === '@company/shared-utils');
      assert.equal(sharedUtils.isFirstParty, true);
      assert.equal(sharedUtils.classification, 'first-party');

      const cloudSdk = result.classifiedComponents.find(c => c.name === '@company/cloud-sdk');
      assert.equal(cloudSdk.isFirstParty, false);
      assert.equal(cloudSdk.classification, 'third-party');

      const react = result.classifiedComponents.find(c => c.name === 'react');
      assert.equal(react.isFirstParty, false);
      assert.equal(react.classification, 'third-party');
    });
  });

  describe('Glob pattern handling, negation, wildcards, and root escaping', () => {
    it('avoids duplicate workspace discovery when patterns overlap', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-overlapping-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'complete');
      // packages/* and packages/pkg-a overlap, but pkg-a should only be discovered once
      assert.equal(result.workspaces.length, 2);

      const pkgAEntries = result.workspaces.filter(w => w.name === 'pkg-a');
      assert.equal(pkgAEntries.length, 1, 'pkg-a must only be discovered once');

      const pkgBEntries = result.workspaces.filter(w => w.name === 'pkg-b');
      assert.equal(pkgBEntries.length, 1, 'pkg-b must only be discovered once');
    });

    it('supports *, **, and ? wildcards in workspace patterns', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-wildcards-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-1'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-2'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-abc'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'nested', 'deep', 'pkg-sub'), { recursive: true });

        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'wildcard-project',
            version: '1.0.0',
            // packages/pkg-? matches pkg-1 and pkg-2, but not pkg-abc; nested/** matches pkg-sub
            workspaces: ['packages/pkg-?', 'nested/**'],
          })
        );

        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-1', 'package.json'),
          JSON.stringify({ name: 'pkg-1', version: '1.0.0' })
        );
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-2', 'package.json'),
          JSON.stringify({ name: 'pkg-2', version: '1.0.0' })
        );
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-abc', 'package.json'),
          JSON.stringify({ name: 'pkg-abc', version: '1.0.0' })
        );
        fs.writeFileSync(
          path.join(tmpDir, 'nested', 'deep', 'pkg-sub', 'package.json'),
          JSON.stringify({ name: 'pkg-sub', version: '1.0.0' })
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);
        assert.equal(result.status, 'complete');

        const names = result.workspaces.map(w => w.name).sort();
        // pkg-1 and pkg-2 matched by ?, pkg-sub matched by **, pkg-abc NOT matched by ?
        assert.deepEqual(names, ['pkg-1', 'pkg-2', 'pkg-sub']);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('supports negated workspace patterns (!pattern) and overlapping exclusions', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-negation-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-a'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-b'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages', 'pkg-c'), { recursive: true });

        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'negation-project',
            version: '1.0.0',
            // Include packages/* but exclude pkg-b
            workspaces: ['packages/*', '!packages/pkg-b'],
          })
        );

        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-a', 'package.json'),
          JSON.stringify({ name: 'pkg-a', version: '1.0.0' })
        );
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-b', 'package.json'),
          JSON.stringify({ name: 'pkg-b', version: '1.0.0' })
        );
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'pkg-c', 'package.json'),
          JSON.stringify({ name: 'pkg-c', version: '1.0.0' })
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);
        assert.equal(result.status, 'complete');

        const names = result.workspaces.map(w => w.name).sort();
        assert.deepEqual(names, ['pkg-a', 'pkg-c'], 'pkg-b must be excluded by negative pattern');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('resolves internal symbolic links within project root', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-symlink-ok-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'internal', 'linked-pkg'), { recursive: true });
        fs.mkdirSync(path.join(tmpDir, 'packages'), { recursive: true });

        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'internal-symlink-project',
            version: '1.0.0',
            workspaces: ['packages/*'],
          })
        );

        fs.writeFileSync(
          path.join(tmpDir, 'internal', 'linked-pkg', 'package.json'),
          JSON.stringify({ name: 'linked-pkg', version: '1.0.0' })
        );

        // Create internal symlink: packages/symlink-pkg -> internal/linked-pkg
        fs.symlinkSync(
          path.join(tmpDir, 'internal', 'linked-pkg'),
          path.join(tmpDir, 'packages', 'symlink-pkg'),
          'dir'
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);
        assert.equal(result.status, 'complete');
        const ws = result.workspaces.find(w => w.name === 'linked-pkg');
        assert.ok(ws, 'Internal symlink package must be discovered');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects workspace paths and symlinks that escape target project root', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-escape-${Date.now()}`);
      const outsideDir = path.join(os.tmpdir(), `test-outside-pkg-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'packages'), { recursive: true });
        fs.mkdirSync(outsideDir, { recursive: true });

        // Outside package
        fs.writeFileSync(
          path.join(outsideDir, 'package.json'),
          JSON.stringify({ name: 'outside-pkg', version: '1.0.0' })
        );

        // Create symlink pointing outside project root
        fs.symlinkSync(outsideDir, path.join(tmpDir, 'packages', 'escaped-symlink'), 'dir');

        // Project root declaring escaping pattern ../outside as well as packages/*
        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'escape-project',
            version: '1.0.0',
            workspaces: ['packages/*', '../outside'],
          })
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);
        assert.equal(result.status, 'partial');

        // Check escaping pattern error
        assert.ok(
          result.errors.some(
            e => e.code === 'UNSUPPORTED_WORKSPACE_LAYOUT' && e.message.includes('escapes project root')
          ),
          'Escaping pattern ../outside must report UNSUPPORTED_WORKSPACE_LAYOUT'
        );

        // Check escaping symlink error
        assert.ok(
          result.errors.some(
            e =>
              e.code === 'UNSUPPORTED_WORKSPACE_LAYOUT' &&
              e.message.includes('resolves outside project root')
          ),
          'Symlink resolving outside project root must report UNSUPPORTED_WORKSPACE_LAYOUT'
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
        fs.rmSync(outsideDir, { recursive: true, force: true });
      }
    });
  });

  describe('Duplicate identifiers & disambiguation', () => {
    it('detects duplicate workspace names and maintains unambiguous bomRefs and graph keys', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-duplicate-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'partial');
      const duplicateError = result.errors.find(
        e => e.code === 'UNSUPPORTED_WORKSPACE_LAYOUT' && e.message.includes('Duplicate workspace package name')
      );
      assert.ok(duplicateError, 'Should report UNSUPPORTED_WORKSPACE_LAYOUT for duplicate package names');
      assert.equal(duplicateError.packageName, 'duplicate-pkg');

      // Check bomRefs are unique (no collisions)
      const bomRefs = result.workspaces.map(w => w.bomRef);
      const uniqueBomRefs = new Set(bomRefs);
      assert.equal(uniqueBomRefs.size, bomRefs.length, 'bomRefs must remain unambiguous');

      // Check dependencyEdges has distinct keys
      for (const ref of bomRefs) {
        assert.ok(result.dependencyEdges[ref] !== undefined);
      }
    });

    it('detects workspace package with same name as root project and disambiguates identifiers', () => {
      const tmpDir = path.join(os.tmpdir(), `test-ws-root-collision-${Date.now()}`);
      try {
        fs.mkdirSync(path.join(tmpDir, 'packages', 'core'), { recursive: true });

        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'collision-monorepo',
            version: '1.0.0',
            workspaces: ['packages/*'],
          })
        );

        // Workspace package has the same name as root project
        fs.writeFileSync(
          path.join(tmpDir, 'packages', 'core', 'package.json'),
          JSON.stringify({
            name: 'collision-monorepo',
            version: '1.0.0',
          })
        );

        const result = discoverFirstPartyComponentsSync(tmpDir);

        assert.equal(result.status, 'partial');
        assert.ok(
          result.errors.some(
            e =>
              e.code === 'UNSUPPORTED_WORKSPACE_LAYOUT' &&
              e.isRootConflict === true &&
              e.message.includes('same name')
          ),
          'Collision with root package name must report UNSUPPORTED_WORKSPACE_LAYOUT'
        );

        // Root and workspace must have distinct, unambiguous bomRefs
        assert.notEqual(
          result.root.bomRef,
          result.workspaces[0].bomRef,
          'Root and workspace bomRefs must be disambiguated'
        );
        assert.ok(
          result.dependencyEdges[result.root.bomRef] !== undefined &&
            result.dependencyEdges[result.workspaces[0].bomRef] !== undefined,
          'Graph keys must remain unambiguous'
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('Missing and invalid workspace files', () => {
    it('returns PROJECT_NOT_FOUND for non-existent target path', async () => {
      const result = await discoverFirstPartyComponents('/nonexistent/path/to/project');
      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PROJECT_NOT_FOUND for invalid path types (empty, null, undefined, non-string)', async () => {
      const emptyResult = await discoverFirstPartyComponents('');
      assert.equal(emptyResult.status, 'failed');
      assert.ok(emptyResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));

      const nullResult = await discoverFirstPartyComponents(null);
      assert.equal(nullResult.status, 'failed');
      assert.ok(nullResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));

      const undefResult = await discoverFirstPartyComponents(undefined);
      assert.equal(undefResult.status, 'failed');
      assert.ok(undefResult.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PROJECT_NOT_FOUND when target path is a file', async () => {
      const filePath = path.join(fixturesDir, 'simple-project', 'package.json');
      const result = await discoverFirstPartyComponents(filePath);
      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'PROJECT_NOT_FOUND'));
    });

    it('returns PACKAGE_FILE_NOT_FOUND when root package.json is missing', async () => {
      const targetPath = path.join(fixturesDir, 'missing-manifest-project');
      const result = await discoverFirstPartyComponents(targetPath);
      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'PACKAGE_FILE_NOT_FOUND'));
    });

    it('returns INVALID_PACKAGE_FILE when root package.json has malformed JSON', async () => {
      const targetPath = path.join(fixturesDir, 'invalid-project');
      const result = await discoverFirstPartyComponents(targetPath);
      assert.equal(result.status, 'failed');
      assert.ok(result.errors.some(e => e.code === 'INVALID_PACKAGE_FILE'));
    });

    it('reports errors for missing and malformed workspace package.json while still discovering valid packages', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-invalid-project');
      const result = await discoverFirstPartyComponents(targetPath);

      assert.equal(result.status, 'partial');

      // Missing workspace manifest error
      assert.ok(
        result.errors.some(
          e => e.code === 'PACKAGE_FILE_NOT_FOUND' && e.message.includes('missing-manifest')
        ),
        'Should report PACKAGE_FILE_NOT_FOUND for directory without package.json'
      );

      // Malformed workspace manifest error
      assert.ok(
        result.errors.some(
          e => e.code === 'INVALID_PACKAGE_FILE' && (e.path?.includes('malformed-manifest') || e.message?.includes('malformed-manifest'))
        ),
        'Should report INVALID_PACKAGE_FILE for malformed package.json'
      );

      // Valid package should still be discovered
      const validPkg = result.workspaces.find(w => w.name === 'valid-pkg');
      assert.ok(validPkg, 'Valid package in the same workspace layout must still be discovered');
    });

    it('reports UNSUPPORTED_WORKSPACE_LAYOUT for invalid workspaces configuration format', async () => {
      const tmpDir = path.join(fixturesDir, 'temp-invalid-config');
      try {
        fs.mkdirSync(tmpDir, { recursive: true });
        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'invalid-config-project',
            version: '1.0.0',
            workspaces: 12345, // invalid
          })
        );

        const result = await discoverFirstPartyComponents(tmpDir);
        assert.equal(result.status, 'failed');
        assert.ok(result.errors.some(e => e.code === 'UNSUPPORTED_WORKSPACE_LAYOUT'));
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('reports warning when workspace pattern matches no packages', async () => {
      const tmpDir = path.join(fixturesDir, 'temp-empty-pattern');
      try {
        fs.mkdirSync(tmpDir, { recursive: true });
        fs.writeFileSync(
          path.join(tmpDir, 'package.json'),
          JSON.stringify({
            name: 'empty-pattern-project',
            version: '1.0.0',
            workspaces: ['nonexistent-packages/*'],
          })
        );

        const result = await discoverFirstPartyComponents(tmpDir);
        assert.equal(result.status, 'complete');
        assert.ok(
          result.warnings.some(
            w => w.code === 'UNSUPPORTED_WORKSPACE_LAYOUT' && w.message.includes('matched no packages')
          )
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });

  describe('Sync and async parity across all fixtures', () => {
    const fixtureNames = [
      'workspace-simple-project',
      'workspace-multi-project',
      'workspace-overlapping-project',
      'workspace-duplicate-project',
      'workspace-invalid-project',
      'simple-project',
      'missing-manifest-project',
      'invalid-project',
    ];

    for (const name of fixtureNames) {
      it(`produces identical results between sync and async for ${name}`, async () => {
        const fixturePath = path.join(fixturesDir, name);
        const asyncResult = await discoverFirstPartyComponents(fixturePath);
        const syncResult = discoverFirstPartyComponentsSync(fixturePath);

        assert.deepEqual(asyncResult, syncResult);
      });
    }

    it('produces identical results for non-existent and invalid paths', async () => {
      const nonExistentPath = '/does/not/exist/path';
      const asyncErr = await discoverFirstPartyComponents(nonExistentPath);
      const syncErr = discoverFirstPartyComponentsSync(nonExistentPath);
      assert.deepEqual(asyncErr, syncErr);
    });
  });

  describe('API surface and aliases', () => {
    it('provides synchronous discovery via discoverFirstPartyComponentsSync', () => {
      const targetPath = path.join(fixturesDir, 'workspace-simple-project');
      const syncResult = discoverFirstPartyComponentsSync(targetPath);

      assert.equal(syncResult.status, 'complete');
      assert.equal(syncResult.root.name, 'workspace-simple-project');
      assert.equal(syncResult.workspaces.length, 1);
    });

    it('aliases discoverWorkspaces and discoverWorkspacesSync to first-party discovery', async () => {
      const targetPath = path.join(fixturesDir, 'workspace-simple-project');

      const asyncResult = await discoverWorkspaces(targetPath);
      assert.equal(asyncResult.status, 'complete');
      assert.equal(asyncResult.root.name, 'workspace-simple-project');

      const syncResult = discoverWorkspacesSync(targetPath);
      assert.equal(syncResult.status, 'complete');
      assert.equal(syncResult.root.name, 'workspace-simple-project');
    });
  });
});
