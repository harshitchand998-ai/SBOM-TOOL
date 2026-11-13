import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateStructure } from '../src/validator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cliScriptPath = path.join(__dirname, '..', 'src', 'cli.js');
const fixturesDir = path.join(__dirname, '..', 'fixtures');

describe('CLI Commands Integration Suite', () => {

  // ==========================================
  // 1. Scan Command Tests
  // ==========================================
  describe('Command: scan', () => {
    it('scans a valid project and displays human-readable summary', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const stdout = execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath], {
        encoding: 'utf8',
      });

      assert.ok(stdout.includes('Scanning project:'));
      assert.ok(stdout.includes('Scan status: complete'));
      assert.ok(stdout.includes('Project: simple-project@1.0.0'));
      assert.ok(stdout.includes('Lockfile version: 3'));
      assert.ok(stdout.includes('Components discovered: 2'));
      assert.ok(stdout.includes('Direct dependencies: 1'));
      assert.ok(stdout.includes('Transitive dependencies: 1'));
    });

    it('scans a workspace project and reports discovered workspace packages', () => {
      const fixturePath = path.join(fixturesDir, 'workspace-with-lockfile-project');
      const stdout = execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath], {
        encoding: 'utf8',
      });

      assert.ok(stdout.includes('Scan status: complete'));
      assert.ok(stdout.includes('Workspace packages: 2'));
    });

    it('outputs valid structured JSON when --json is passed without console logs', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const stdout = execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath, '--json'], {
        encoding: 'utf8',
      });

      const parsed = JSON.parse(stdout);
      assert.equal(parsed.status, 'complete');
      assert.equal(parsed.projectMetadata.name, 'simple-project');
      assert.ok(Array.isArray(parsed.components));
      assert.equal(parsed.components.length, 3); // root + is-odd + is-number
    });

    it('writes generated CycloneDX SBOM to specified file with -o', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-scan-out-'));
      const targetPath = path.join(tmpDir, 'output.cdx.json');

      try {
        const stdout = execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath, '-o', targetPath], {
          encoding: 'utf8',
        });

        assert.ok(stdout.includes('CycloneDX SBOM written to:'));
        assert.ok(fs.existsSync(targetPath));
        const bom = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
        const validation = validateStructure(bom);
        assert.equal(validation.valid, true);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('handles partial scan correctly by generating .partial.json', () => {
      const fixturePath = path.join(fixturesDir, 'missing-lockfile-project');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-scan-part-'));
      const targetPath = path.join(tmpDir, 'report.cdx.json');
      const expectedPartial = path.join(tmpDir, 'report.partial.json');

      try {
        const stdout = execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath, '--output', targetPath], {
          encoding: 'utf8',
        });

        assert.ok(stdout.includes('Partial scan completed'));
        assert.equal(fs.existsSync(targetPath), false);
        assert.equal(fs.existsSync(expectedPartial), true);
        const report = JSON.parse(fs.readFileSync(expectedPartial, 'utf8'));
        assert.equal(report.scanStatus, 'partial');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('fails with code 1 for invalid project manifest', () => {
      const fixturePath = path.join(fixturesDir, 'invalid-project');
      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        return true;
      });
    });

    it('fails with code 1 when missing manifest project is scanned', () => {
      const fixturePath = path.join(fixturesDir, 'missing-manifest-project');
      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'scan', fixturePath], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        return true;
      });
    });
  });

  // ==========================================
  // 2. SBOM Command Tests
  // ==========================================
  describe('Command: sbom', () => {
    it('generates a valid CycloneDX SBOM and writes to user-specified file', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-sbom-file-'));
      const targetPath = path.join(tmpDir, 'custom-bom.json');

      try {
        const stdout = execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath, '-o', targetPath], {
          encoding: 'utf8',
        });

        assert.ok(stdout.includes(`CycloneDX SBOM written to: ${targetPath}`));
        assert.ok(fs.existsSync(targetPath));
        const bom = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
        assert.equal(bom.bomFormat, 'CycloneDX');
        assert.equal(bom.specVersion, '1.7');
        const validation = validateStructure(bom);
        assert.equal(validation.valid, true);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('generates a valid CycloneDX SBOM and outputs JSON to stdout with --json', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const stdout = execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath, '--json'], {
        encoding: 'utf8',
      });

      const bom = JSON.parse(stdout);
      assert.equal(bom.bomFormat, 'CycloneDX');
      assert.equal(bom.specVersion, '1.7');
      assert.equal(bom.metadata.component.name, 'simple-project');
      assert.equal(bom.components.length, 2);
      const componentNames = bom.components.map(c => c.name);
      assert.ok(componentNames.includes('is-odd'));
      assert.ok(componentNames.includes('is-number'));
      const validation = validateStructure(bom);
      assert.equal(validation.valid, true);
    });

    it('creates nested destination directory automatically if missing', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-sbom-nested-'));
      const targetPath = path.join(tmpDir, 'nested', 'deeply', 'reports', 'bom.cdx.json');

      try {
        execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath, '--output', targetPath], {
          encoding: 'utf8',
        });

        assert.ok(fs.existsSync(targetPath));
        const bom = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
        assert.equal(bom.bomFormat, 'CycloneDX');
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects output path pointing to an existing directory', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cli-sbom-dir-'));

      try {
        assert.throws(() => {
          execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath, '--output', tmpDir], {
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
          });
        }, (err) => {
          assert.equal(err.status, 1);
          assert.ok(err.stderr.includes('must be a file, not a directory'));
          return true;
        });
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('rejects output path attempting to overwrite project package.json', () => {
      const fixturePath = path.join(fixturesDir, 'simple-project');
      const pkgPath = path.join(fixturePath, 'package.json');

      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath, '--output', pkgPath], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        assert.ok(err.stderr.includes('Cannot overwrite project file'));
        return true;
      });
    });

    it('rejects partial scan projects where lockfile is missing', () => {
      const fixturePath = path.join(fixturesDir, 'missing-lockfile-project');

      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        assert.ok(err.stderr.includes('package-lock.json is required'));
        return true;
      });
    });

    it('fails with code 1 when scanning invalid project for SBOM generation', () => {
      const fixturePath = path.join(fixturesDir, 'invalid-project');

      assert.throws(() => {
        execFileSync(process.execPath, [cliScriptPath, 'sbom', fixturePath], {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      }, (err) => {
        assert.equal(err.status, 1);
        return true;
      });
    });
  });
});
