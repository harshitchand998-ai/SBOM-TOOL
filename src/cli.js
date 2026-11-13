#!/usr/bin/env node

/**
 * Command-line interface for SBOM-TOOL.
 *
 * Supported commands:
 *   scan    Scan an npm project and inspect its dependencies.
 *   sbom    Generate a CycloneDX SBOM for the selected project.
 *   audit   Perform security vulnerability and anomaly analysis on a project.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
  executeScan,
  executeSbom,
  executeAudit,
  buildCombinedReport,
  writeMultiFileOutput,
  computeSeverityCounts,
} from './engine/index.js';
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
  sbom     Generate a CycloneDX SBOM for the selected project.
  audit    Perform vulnerability and anomaly analysis on a project.

Global Options:
  --help, -h       Show help for sbom-tool or a specific command.
  --version, -V    Show version number.

Run "sbom-tool <command> --help" for detailed information on a specific command.

Examples:
  sbom-tool scan ./my-project
  sbom-tool scan ./my-project --full
  sbom-tool sbom ./my-project --output ./reports/sbom.cdx.json
  sbom-tool audit ./my-project --vuln --anomaly
`);
}

function printScanHelp() {
  console.log(`sbom-tool scan — Scan an npm project and inspect its dependencies

Usage:
  sbom-tool scan <project-path> [options]

Options:
  --full                 Perform complete scan (SBOM generation, validation, vulnerabilities, anomalies, and comparison if --previous-sbom provided).
  --output, -o <path>    Write scan report (or generated SBOM) to file, or output directory with --full.
  --output-dir <path>    Directory to write multi-file report (sbom.json, vulnerabilities.json, anomalies.json, report.json).
  --json                 Output structured scan results in JSON format to stdout.
  --vulnerabilities, -v  Enable OSV vulnerability analysis for discovered dependencies.
  --anomalies, -a        Enable anomaly detection explicitly.
  --previous-sbom <path> Path to a previous CycloneDX SBOM JSON file for dependency comparison.
  --help, -h             Show this help message.

Examples:
  sbom-tool scan .
  sbom-tool scan ./my-project
  sbom-tool scan ./my-project --full
  sbom-tool scan ./my-project --json
  sbom-tool scan ./my-project --output ./scan-report.json
  sbom-tool scan ./my-project --output-dir ./reports
  sbom-tool scan ./my-project --vulnerabilities
  sbom-tool scan ./my-project --previous-sbom ./prev.cdx.json
`);
}

function printSbomHelp() {
  console.log(`sbom-tool sbom — Generate a CycloneDX SBOM for the selected project

Usage:
  sbom-tool sbom <project-path> [options]

Options:
  --output, -o <path>    Output file path for the generated CycloneDX SBOM.
                         (Default: ./sbom.cdx.json when not writing to stdout)
  --json                 Output CycloneDX SBOM JSON directly to stdout.
  --help, -h             Show this help message.

Examples:
  sbom-tool sbom .
  sbom-tool sbom ./my-project
  sbom-tool sbom ./my-project --output ./bom.cdx.json
  sbom-tool sbom ./my-project -o ./reports/sbom.json
  sbom-tool sbom ./my-project --json > sbom.json
`);
}

function printAuditHelp() {
  console.log(`sbom-tool audit — Perform vulnerability and anomaly analysis on a project

Usage:
  sbom-tool audit <project-path> [options]

Options:
  --vuln, -v             Perform vulnerability analysis only (or explicitly).
  --anomaly, -a          Perform anomaly analysis only (or explicitly).
  --previous-sbom <path> Path to a previous CycloneDX SBOM JSON file for dependency comparison.
  --output, -o <path>    Output file path for the structured audit report JSON.
  --json                 Output structured audit report JSON directly to stdout.
  --help, -h             Show this help message.

Note:
  When neither --vuln nor --anomaly is specified, both analyses are performed by default.

Examples:
  sbom-tool audit .
  sbom-tool audit ./my-project
  sbom-tool audit ./my-project --vuln
  sbom-tool audit ./my-project --anomaly
  sbom-tool audit ./my-project --vuln --anomaly
  sbom-tool audit ./my-project --previous-sbom ./prev.cdx.json
  sbom-tool audit ./my-project --output ./audit-report.json
  sbom-tool audit ./my-project --json
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

  // Check if output is directory or single file
  let resolvedOutput = null;
  let isDirectoryOutput = Boolean(options.outputDir);

  if (options.outputDir) {
    resolvedOutput = path.resolve(options.outputDir);
    isDirectoryOutput = true;
  } else if (options.output) {
    const rawOut = path.resolve(options.output);
    if (options.full && (!rawOut.endsWith('.json') || (fs.existsSync(rawOut) && fs.statSync(rawOut).isDirectory()))) {
      resolvedOutput = rawOut;
      isDirectoryOutput = true;
    } else if (fs.existsSync(rawOut) && fs.statSync(rawOut).isDirectory()) {
      if (options.full) {
        resolvedOutput = rawOut;
        isDirectoryOutput = true;
      } else {
        console.error(`Error: Output path must be a file, not a directory: ${options.output}`);
        process.exit(1);
      }
    } else {
      resolvedOutput = validateOutputPath(options.output, resolvedProject);
      isDirectoryOutput = false;
    }
  } else if (options.full && !options.json) {
    // Default output directory for --full scan
    resolvedOutput = path.resolve('./output');
    isDirectoryOutput = true;
  }

  const result = await executeScan(projectPath, options);

  // If JSON output requested on stdout
  if (options.json) {
    if (options.full) {
      const combinedReport = buildCombinedReport(result, options);
      process.stdout.write(JSON.stringify(combinedReport, null, 2) + '\n');
    } else {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    }

    if (resolvedOutput) {
      if (isDirectoryOutput) {
        try {
          writeMultiFileOutput(resolvedOutput, result, options);
        } catch (err) {
          console.error(`Error: Failed to write output directory "${resolvedOutput}": ${err.message}`);
          process.exit(1);
        }
      } else {
        writeJsonFile(resolvedOutput, result);
      }
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

  // Vulnerability analysis section (when requested or in full scan)
  if (options.vulnerabilities || options.full) {
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

  // Anomaly detection results
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

  // Dependency comparison results
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

  // File output handling
  if (resolvedOutput) {
    if (isDirectoryOutput) {
      try {
        const written = writeMultiFileOutput(resolvedOutput, result, options);
        console.log(`Generated report files in: ${resolvedOutput}`);
        if (written.sbom) console.log(`  • CycloneDX SBOM: ${written.sbom}`);
        if (written.vulnerabilities) console.log(`  • Vulnerabilities: ${written.vulnerabilities}`);
        if (written.anomalies) console.log(`  • Anomalies: ${written.anomalies}`);
        if (written.report) console.log(`  • Combined Report: ${written.report}`);
        if (written.cleanupWarning) console.warn(`  ⚠ [${written.cleanupWarning.code}] ${written.cleanupWarning.message}`);
      } catch (err) {
        console.error(`Error: Failed to write output directory "${resolvedOutput}": ${err.message}`);
        process.exit(1);
      }
    } else {
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
  }

  const hasValidationError = result.validation && !result.validation.valid;
  process.exit((result.status === ScanStatus.FAILED || hasValidationError) ? 1 : 0);
}

/**
 * Executes the 'sbom' command.
 */
async function handleSbom(projectPath, options) {
  const resolvedProject = path.resolve(projectPath);

  let resolvedOutput = null;
  if (options.output) {
    resolvedOutput = validateOutputPath(options.output, resolvedProject);
  } else if (!options.json) {
    // Default output path when --json is not specified
    resolvedOutput = validateOutputPath('./sbom.cdx.json', resolvedProject);
  }

  const sbomResult = await executeSbom(projectPath, options);

  if (!sbomResult.success) {
    console.error(`Error: ${sbomResult.message}`);
    if (sbomResult.errors && sbomResult.errors.length > 0) {
      for (const err of sbomResult.errors) {
        const msg = typeof err === 'string' ? err : err.message;
        const code = err?.code ? `[${err.code}] ` : '';
        console.error(`  ✗ ${code}${msg}`);
      }
    }
    process.exit(1);
  }

  if (resolvedOutput) {
    writeJsonFile(resolvedOutput, sbomResult.bom);
    if (!options.json) {
      console.log(`CycloneDX SBOM written to: ${resolvedOutput}`);
    }
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(sbomResult.bom, null, 2) + '\n');
  }

  process.exit(0);
}

/**
 * Executes the 'audit' command.
 */
async function handleAudit(projectPath, options) {
  const resolvedProject = path.resolve(projectPath);

  let resolvedOutput = null;
  if (options.output) {
    resolvedOutput = validateOutputPath(options.output, resolvedProject);
  }

  const auditReport = await executeAudit(projectPath, options);

  if (!auditReport.success) {
    console.error('Error: Project scan failed. Unable to perform audit.');
    if (auditReport.errors && auditReport.errors.length > 0) {
      for (const err of auditReport.errors) {
        console.error(`  ✗ [${err.code || 'SCAN_ERROR'}] ${err.message}`);
      }
    }
    process.exit(1);
  }

  // Handle output file
  if (resolvedOutput) {
    writeJsonFile(resolvedOutput, auditReport);
  }

  // Handle JSON stdout
  if (options.json) {
    process.stdout.write(JSON.stringify(auditReport, null, 2) + '\n');
    process.exit(0);
  }

  // Human-readable terminal output
  console.log('Security Audit');
  console.log();
  console.log(`Project: ${auditReport.project.name}@${auditReport.project.version}`);
  console.log(`Path: ${auditReport.project.path}`);
  console.log();
  console.log(`Dependencies scanned: ${auditReport.summary.dependenciesScanned}`);
  console.log();

  if (auditReport.vulnerabilities) {
    const vulnData = auditReport.vulnerabilities;
    console.log('--- Vulnerabilities ---');
    console.log(`Status: ${vulnData.status.toUpperCase()}`);
    console.log(`Packages checked: ${vulnData.scannedPackages}/${vulnData.totalPackages}`);
    console.log(`Vulnerabilities found: ${vulnData.findings?.length || 0}`);

    const sev = computeSeverityCounts(vulnData.findings);
    console.log(`Critical: ${sev.critical}`);
    console.log(`High: ${sev.high}`);
    console.log(`Medium: ${sev.medium}`);
    console.log(`Low: ${sev.low}`);
    if (sev.unknown > 0) {
      console.log(`Unknown severity: ${sev.unknown}`);
    }
    console.log();

    if (vulnData.errors && vulnData.errors.length > 0) {
      console.log(`Vulnerability query errors (${vulnData.errors.length}):`);
      for (const err of vulnData.errors) {
        const pkgStr = err.package ? `${err.package.name}@${err.package.version}` : 'unknown';
        console.error(`  ✗ [${err.code || 'QUERY_ERROR'}] ${pkgStr}: ${err.error}`);
      }
      console.log();
    }

    if (vulnData.findings && vulnData.findings.length > 0) {
      console.log('Vulnerability Findings:');
      for (const f of vulnData.findings) {
        const sevStr = f.severity ? `[${f.severity.type}: ${f.severity.score}]` : '[SEVERITY: UNKNOWN]';
        const fixStr = f.fixedVersions?.length > 0 ? ` (Fixed in: ${f.fixedVersions.join(', ')})` : ' (No fix available)';
        console.log(`  • ${f.id} ${sevStr} - ${f.packageName}@${f.installedVersion} (${f.dependencyType})${fixStr}`);
        if (f.summary) {
          console.log(`    Summary: ${f.summary}`);
        }
      }
      console.log();
    } else if (vulnData.status === 'completed') {
      console.log('✔ No known vulnerabilities found.');
      console.log();
    } else if (vulnData.status === 'partial') {
      console.log('⚠ Incomplete vulnerability analysis: Some packages could not be checked due to errors.');
      console.log();
    }
  }

  if (auditReport.anomalies) {
    console.log('--- Anomalies ---');
    const a = auditReport.anomalies;
    console.log(`Anomalies detected: ${a.total} (errors: ${a.bySeverity.error}, warnings: ${a.bySeverity.warning}, info: ${a.bySeverity.info})`);

    if (a.findings && a.findings.length > 0) {
      for (const f of a.findings) {
        const compName = f.component?.name || f.component?.bomRef || 'unknown';
        console.log(`  ${f.severity === 'error' ? '✗' : f.severity === 'warning' ? '⚠' : 'ℹ'} [${f.type}] ${compName}: ${f.message}`);
      }
    } else {
      console.log('✔ No anomalies detected.');
    }
    console.log();
  }

  if (auditReport.comparison) {
    console.log('--- Dependency Comparison ---');
    const c = auditReport.comparison;
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

  if (resolvedOutput) {
    console.log(`Audit report written to: ${resolvedOutput}`);
    console.log();
  }

  console.log(`Audit completed (Status: ${auditReport.status}).`);
  process.exit(0);
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
  const supportedCommands = ['scan', 'sbom', 'audit'];

  if (!supportedCommands.includes(command)) {
    console.error(`Error: Unknown command "${command}". Available commands: scan, sbom, audit`);
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
      else if (command === 'sbom') printSbomHelp();
      else if (command === 'audit') printAuditHelp();
      process.exit(0);
    }

    if (arg === '--output' || arg === '-o') {
      if (i + 1 >= remaining.length || remaining[i + 1].startsWith('-')) {
        console.error('Error: --output requires a file path argument.');
        process.exit(1);
      }
      options.output = remaining[i + 1];
      i++;
    } else if (arg === '--output-dir') {
      if (i + 1 >= remaining.length || remaining[i + 1].startsWith('-')) {
        console.error('Error: --output-dir requires a directory path argument.');
        process.exit(1);
      }
      options.outputDir = remaining[i + 1];
      i++;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--full' && command === 'scan') {
      options.full = true;
    } else if (arg === '--vulnerabilities' || (command === 'scan' && arg === '-v')) {
      options.vulnerabilities = true;
    } else if (arg === '--vuln' || (command === 'audit' && arg === '-v')) {
      options.vuln = true;
    } else if (arg === '--anomalies' || arg === '--anomaly' || (command === 'audit' && arg === '-a') || (command === 'scan' && arg === '-a')) {
      options.anomaly = true;
      options.anomalies = true;
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
    else if (command === 'sbom') printSbomHelp();
    else if (command === 'audit') printAuditHelp();
    process.exit(1);
  }

  const resolvedProject = path.resolve(projectPath);
  if (!fs.existsSync(resolvedProject)) {
    console.error(`Error: Project path does not exist: ${projectPath}`);
    process.exit(1);
  }

  if (command === 'scan') {
    await handleScan(projectPath, options);
  } else if (command === 'sbom') {
    await handleSbom(projectPath, options);
  } else if (command === 'audit') {
    await handleAudit(projectPath, options);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message || err}`);
  process.exit(1);
});
