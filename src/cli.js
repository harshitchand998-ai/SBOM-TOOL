#!/usr/bin/env node

/**
 * Command-line interface for SBOM-TOOL.
 *
 * Supported commands:
 *   scan    Scan an npm project and inspect its dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from './scanner/index.js';
import { ScanStatus } from './errors.js';

// Resolve tool version from package.json
const pkgJsonPath = new URL('../package.json', import.meta.url);
let VERSION = '0.1.0';
try {
  const pkgData = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  VERSION = pkgData.version || '0.1.0';
} catch {
  // Fallback to default version if unreadable
}

function printGeneralHelp() {
  console.log(`sbom-tool — Software Bill of Materials & Security Analysis CLI (v${VERSION})

Usage:
  sbom-tool <command> [project-path] [options]

Commands:
  scan     Scan an npm project and inspect its dependencies.

Global Options:
  --help, -h       Show help for sbom-tool or a specific command.
  --version, -V    Show version number.

Run "sbom-tool <command> --help" for detailed information on a specific command.

Examples:
  sbom-tool scan ./my-project
`);
}

function printScanHelp() {
  console.log(`sbom-tool scan — Scan an npm project and inspect its dependencies

Usage:
  sbom-tool scan <project-path> [options]

Options:
  --output, -o <path>    Write scan report (or generated SBOM) to file.
  --json                 Output structured scan results in JSON format to stdout.
  --vulnerabilities, -v  Enable OSV vulnerability analysis for discovered dependencies.
  --previous-sbom <path> Path to a previous CycloneDX SBOM JSON file for dependency comparison.
  --help, -h             Show this help message.

Examples:
  sbom-tool scan .
  sbom-tool scan ./my-project
  sbom-tool scan ./my-project --json
  sbom-tool scan ./my-project --output ./scan-report.json
  sbom-tool scan ./my-project --vulnerabilities
  sbom-tool scan ./my-project --previous-sbom ./prev.cdx.json
`);
}

function validateOutputPath(outputPath, resolvedProject) {
  const resolvedOutput = path.resolve(outputPath);

  if (fs.existsSync(resolvedOutput) && fs.statSync(resolvedOutput).isDirectory()) {
    console.error(`Error: Output path must be a file, not a directory: ${outputPath}`);
    process.exit(1);
  }

  const pkgJsonPath = path.resolve(resolvedProject, 'package.json');
  const lockJsonPath = path.resolve(resolvedProject, 'package-lock.json');
  if (resolvedOutput === pkgJsonPath || resolvedOutput === lockJsonPath) {
    console.error(`Error: Cannot overwrite project file: ${outputPath}`);
    process.exit(1);
  }

  return resolvedOutput;
}

function writeJsonFile(filePath, data) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error(`Error: Failed to write output file "${filePath}": ${err.message}`);
    process.exit(1);
  }
}

/**
 * Executes the 'scan' command.
 */
async function handleScan(projectPath, options) {
  const resolvedProject = path.resolve(projectPath);
  let resolvedOutput = null;
  if (options.output) {
    resolvedOutput = validateOutputPath(options.output, resolvedProject);
  }

  const scanOptions = { vulnerabilities: Boolean(options.vulnerabilities) };

  if (options.previousSbom) {
    try {
      const prevContent = fs.readFileSync(path.resolve(options.previousSbom), 'utf8');
      scanOptions.previousBom = JSON.parse(prevContent);
    } catch (err) {
      console.error(`Error reading previous SBOM: ${err.message}`);
      process.exit(1);
    }
  }

  const result = await scanProject(projectPath, scanOptions);

  // If JSON output requested on stdout
  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    if (resolvedOutput) {
      writeJsonFile(resolvedOutput, result);
    }
    const hasValidationError = result.validation && !result.validation.valid;
    process.exit((result.status === ScanStatus.FAILED || hasValidationError) ? 1 : 0);
  }

  // Human-readable terminal output
  console.log(`Scanning project: ${resolvedProject}`);
  console.log();
  console.log(`Scan status: ${result.status}`);

  if (result.projectMetadata) {
    console.log(`Project: ${result.projectMetadata.name}@${result.projectMetadata.version}`);
  }

  if (result.lockfileVersion) {
    console.log(`Lockfile version: ${result.lockfileVersion}`);
  }

  const components = Array.isArray(result.components) ? result.components : [];
  const packageCount = components.filter(c => !c.isRoot).length;
  console.log(`Components discovered: ${packageCount}`);

  const directDeps = components.filter(c => !c.isRoot && c.dependencyType === 'direct').length;
  const transitiveDeps = components.filter(c => !c.isRoot && c.dependencyType === 'transitive').length;
  const workspaceDeps = components.filter(c => !c.isRoot && (c.isFirstParty || c.dependencyType === 'workspace')).length;

  if (packageCount > 0) {
    console.log(`Direct dependencies: ${directDeps}`);
    console.log(`Transitive dependencies: ${transitiveDeps}`);
    if (workspaceDeps > 0) {
      console.log(`Workspace packages: ${workspaceDeps}`);
    }
  }
  console.log();

  if (result.warnings && result.warnings.length > 0) {
    console.log(`Warnings (${result.warnings.length}):`);
    for (const w of result.warnings) {
      console.log(`  ⚠ [${w.code}] ${w.message}`);
    }
    console.log();
  }

  if (result.errors && result.errors.length > 0) {
    console.log(`Errors (${result.errors.length}):`);
    for (const e of result.errors) {
      console.error(`  ✗ [${e.code}] ${e.message}`);
    }
    console.log();
  }

  if (result.validation && !result.validation.valid) {
    console.error(`BOM validation failed with ${result.validation.errors.length} error(s):`);
    for (const err of result.validation.errors) {
      console.error(`  ✗ ${err}`);
    }
    console.log();
  }

  // Vulnerability analysis section (when requested)
  if (options.vulnerabilities) {
    console.log('--- Vulnerability Analysis ---');
    if (!result.vulnerabilities) {
      console.log('Vulnerability analysis skipped (complete and valid SBOM required).');
      console.log();
    } else {
      const v = result.vulnerabilities;
      console.log(`Status: ${v.status.toUpperCase()}`);
      console.log(`Packages scanned: ${v.scannedPackages}/${v.totalPackages}`);
      console.log(`Vulnerabilities found: ${v.findings.length}`);
      console.log();

      if (v.warnings && v.warnings.length > 0) {
        for (const warn of v.warnings) {
          console.log(`  ⚠ ${warn}`);
        }
        console.log();
      }

      if (v.errors && v.errors.length > 0) {
        console.log(`Vulnerability query errors (${v.errors.length}):`);
        for (const err of v.errors) {
          const pkgStr = err.package ? `${err.package.name}@${err.package.version}` : 'unknown';
          console.error(`  ✗ [${err.code || 'QUERY_ERROR'}] ${pkgStr}: ${err.error}`);
        }
        console.log();
      }

      if (v.findings.length > 0) {
        console.log('Vulnerability Findings:');
        for (const f of v.findings) {
          const sevStr = f.severity ? `[${f.severity.type}: ${f.severity.score}]` : '[SEVERITY: UNKNOWN]';
          const fixStr = f.fixedVersions?.length > 0 ? ` (Fixed in: ${f.fixedVersions.join(', ')})` : ' (No fix available)';
          console.log(`  • ${f.id} ${sevStr} - ${f.packageName}@${f.installedVersion} (${f.dependencyType})${fixStr}`);
          if (f.summary) {
            console.log(`    Summary: ${f.summary}`);
          }
        }
        console.log();
      } else if (v.status === 'completed') {
        console.log('✔ No known vulnerabilities found.');
        console.log();
      } else if (v.status === 'partial') {
        console.log('⚠ Incomplete analysis: Some packages could not be checked due to errors.');
        console.log();
      }
    }
  }

  // Anomaly detection results (if present in result)
  if (result.anomalies) {
    console.log('--- Anomaly Detection ---');
    const a = result.anomalies;
    console.log(`Total anomalies: ${a.summary.total} (error: ${a.summary.bySeverity.error}, warning: ${a.summary.bySeverity.warning}, info: ${a.summary.bySeverity.info})`);
    if (a.findings.length > 0) {
      for (const f of a.findings) {
        const compName = f.component?.name || f.component?.bomRef || 'unknown';
        console.log(`  ${f.severity === 'error' ? '✗' : f.severity === 'warning' ? '⚠' : 'ℹ'} [${f.type}] ${compName}: ${f.message}`);
      }
    }
    console.log();
  }

  // Dependency comparison results (if present in result)
  if (result.comparison) {
    console.log('--- Dependency Comparison ---');
    const c = result.comparison;
    console.log(`Status: ${c.status}`);
    console.log(`Added: ${c.summary.added}, Removed: ${c.summary.removed}, Changed: ${c.summary.changed}, Unchanged: ${c.summary.unchanged}`);
    for (const item of c.added) {
      console.log(`  + ${item.explanation}`);
    }
    for (const item of c.removed) {
      console.log(`  - ${item.explanation}`);
    }
    for (const item of c.changed) {
      console.log(`  ~ ${item.explanation}`);
    }
    console.log();
  }

  // File output handling when --output is provided
  if (resolvedOutput) {
    if (result.status === ScanStatus.COMPLETE && result.bom && result.validation?.valid) {
      writeJsonFile(resolvedOutput, result.bom);
      console.log(`CycloneDX SBOM written to: ${resolvedOutput}`);
    } else if (result.status === ScanStatus.PARTIAL) {
      if (result.validation && !result.validation.valid) {
        console.log('BOM validation failed. No CycloneDX SBOM generated.');
      } else {
        console.log('Partial scan completed. No CycloneDX SBOM generated (lockfile required for complete scan).');
      }

      const partialOutput = resolvedOutput.endsWith('.cdx.json')
        ? resolvedOutput.replace(/\.cdx\.json$/, '.partial.json')
        : resolvedOutput;
      writeJsonFile(partialOutput, {
        scanStatus: result.status,
        projectMetadata: result.projectMetadata,
        warnings: result.warnings,
        errors: result.errors,
        components: result.components,
        validation: result.validation,
      });
      console.log(`Partial scan report written to: ${partialOutput}`);
    } else {
      console.log('Scan failed. No output generated.');
    }
  }

  const hasValidationError = result.validation && !result.validation.valid;
  process.exit((result.status === ScanStatus.FAILED || hasValidationError) ? 1 : 0);
}

/**
 * Main CLI entry point.
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    printGeneralHelp();
    process.exit(0);
  }

  // Check global flags without command
  if (args[0] === '--help' || args[0] === '-h') {
    printGeneralHelp();
    process.exit(0);
  }

  if (args[0] === '--version' || args[0] === '-V' || (args[0] === '-v' && args.length === 1)) {
    console.log(VERSION);
    process.exit(0);
  }

  const command = args[0];
  const supportedCommands = ['scan'];

  if (!supportedCommands.includes(command)) {
    console.error(`Error: Unknown command "${command}". Available commands: scan`);
    console.error();
    printGeneralHelp();
    process.exit(1);
  }

  // Parse command arguments
  let projectPath = null;
  const options = {};
  const remaining = args.slice(1);

  for (let i = 0; i < remaining.length; i++) {
    const arg = remaining[i];

    if (arg === '--help' || arg === '-h') {
      if (command === 'scan') printScanHelp();
      process.exit(0);
    }

    if (arg === '--output' || arg === '-o') {
      if (i + 1 >= remaining.length || remaining[i + 1].startsWith('-')) {
        console.error('Error: --output requires a file path argument.');
        process.exit(1);
      }
      options.output = remaining[i + 1];
      i++;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--vulnerabilities' || (command === 'scan' && arg === '-v')) {
      options.vulnerabilities = true;
    } else if (arg === '--previous-sbom') {
      if (i + 1 >= remaining.length || remaining[i + 1].startsWith('-')) {
        console.error('Error: --previous-sbom requires a file path argument.');
        process.exit(1);
      }
      options.previousSbom = remaining[i + 1];
      i++;
    } else if (arg.startsWith('-')) {
      console.error(`Error: Unknown option "${arg}".`);
      process.exit(1);
    } else {
      if (projectPath === null) {
        projectPath = arg;
      } else {
        console.error(`Error: Unexpected argument "${arg}".`);
        process.exit(1);
      }
    }
  }

  if (!projectPath) {
    console.error('Error: Project path is required.');
    console.error();
    if (command === 'scan') printScanHelp();
    process.exit(1);
  }

  const resolvedProject = path.resolve(projectPath);
  if (!fs.existsSync(resolvedProject)) {
    console.error(`Error: Project path does not exist: ${projectPath}`);
    process.exit(1);
  }

  if (command === 'scan') {
    await handleScan(projectPath, options);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message || err}`);
  process.exit(1);
});
