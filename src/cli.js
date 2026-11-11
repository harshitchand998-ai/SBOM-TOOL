#!/usr/bin/env node

/**
 * CLI entry point for the npm SBOM scanner.
 *
 * Usage:
 *   node src/cli.js scan <project-path> [--output <output-path>]
 *
 * Examples:
 *   node src/cli.js scan ./my-application
 *   node src/cli.js scan /Users/user/projects/my-app --output ./bom.json
 *   node src/cli.js scan "./path with spaces/app"
 */

import fs from 'node:fs';
import path from 'node:path';
import { scanProject } from './scanner/index.js';

const args = process.argv.slice(2);

function printUsage() {
  console.log(`
npm-sbom-tool — Software Bill of Materials Scanner

Usage:
  node src/cli.js scan <project-path> [--output <output-path>] [--vulnerabilities]

Commands:
  scan    Scan an npm project and generate a CycloneDX SBOM.

Options:
  --output, -o          Output file path for the generated SBOM.
                        Default: ./sbom-output.cdx.json
  --vulnerabilities, -v Enable OSV vulnerability analysis for discovered dependencies.

Examples:
  node src/cli.js scan ./my-application
  node src/cli.js scan /Users/user/projects/app --output ./bom.json
  node src/cli.js scan ./my-application --vulnerabilities
  node src/cli.js scan "./path with spaces/project"
`);
}

async function main() {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    printUsage();
    process.exit(0);
  }

  const command = args[0];

  if (command !== 'scan') {
    console.error(`Unknown command: "${command}". Use "scan" to scan a project.`);
    printUsage();
    process.exit(1);
  }

  if (args.length < 2) {
    console.error('Error: Project path is required.');
    printUsage();
    process.exit(1);
  }

  const projectPath = args[1];
  let outputPath = './sbom-output.cdx.json';
  let checkVulns = false;

  // Parse optional arguments
  for (let i = 2; i < args.length; i++) {
    if (args[i] === '--output' || args[i] === '-o') {
      if (i + 1 >= args.length) {
        console.error('Error: --output requires a file path argument.');
        process.exit(1);
      }
      outputPath = args[i + 1];
      i++; // skip the value
    } else if (args[i] === '--vulnerabilities' || args[i] === '-v') {
      checkVulns = true;
    }
  }

  console.log(`Scanning project: ${path.resolve(projectPath)}`);
  console.log();

  const result = await scanProject(projectPath, { vulnerabilities: checkVulns });

  // Report scan status
  console.log(`Scan status: ${result.status}`);

  if (result.projectMetadata) {
    console.log(`Project: ${result.projectMetadata.name}@${result.projectMetadata.version}`);
  }

  if (result.lockfileVersion) {
    console.log(`Lockfile version: ${result.lockfileVersion}`);
  }

  // Count components (excluding root)
  const packageCount = result.components.filter(c => !c.isRoot).length;
  console.log(`Components discovered: ${packageCount}`);
  console.log();

  // Report warnings
  if (result.warnings.length > 0) {
    console.log(`Warnings (${result.warnings.length}):`);
    for (const w of result.warnings) {
      console.log(`  ⚠ [${w.code}] ${w.message}`);
    }
    console.log();
  }

  // Report errors
  if (result.errors.length > 0) {
    console.log(`Errors (${result.errors.length}):`);
    for (const e of result.errors) {
      console.error(`  ✗ [${e.code}] ${e.message}`);
    }
    console.log();
  }

  // Report validation errors if present
  if (result.validation && !result.validation.valid) {
    console.error(`BOM validation failed with ${result.validation.errors.length} error(s):`);
    for (const err of result.validation.errors) {
      console.error(`  ✗ ${err}`);
    }
    console.log();
  }

  // Report vulnerability analysis if requested
  if (checkVulns) {
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

  // Write output
  if (result.status === 'complete' && result.bom && result.validation?.valid) {
    const resolvedOutput = path.resolve(outputPath);
    const outputDir = path.dirname(resolvedOutput);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    fs.writeFileSync(resolvedOutput, JSON.stringify(result.bom, null, 2), 'utf-8');
    console.log(`CycloneDX SBOM written to: ${resolvedOutput}`);
  } else if (result.status === 'partial') {
    if (result.validation && !result.validation.valid) {
      console.log('BOM validation failed. No CycloneDX SBOM generated.');
    } else {
      console.log('Partial scan completed. No CycloneDX SBOM generated (lockfile required for complete scan).');
    }

    // Write partial result to a JSON report instead
    const partialOutput = outputPath.replace(/\.cdx\.json$/, '.partial.json');
    const resolvedOutput = path.resolve(partialOutput);
    fs.writeFileSync(resolvedOutput, JSON.stringify({
      scanStatus: result.status,
      projectMetadata: result.projectMetadata,
      warnings: result.warnings,
      errors: result.errors,
      components: result.components,
      validation: result.validation,
    }, null, 2), 'utf-8');
    console.log(`Partial scan report written to: ${resolvedOutput}`);
  } else {
    console.log('Scan failed. No output generated.');
  }

  // Exit with non-zero if scan failed or if validation failed
  const hasValidationError = result.validation && !result.validation.valid;
  process.exit((result.status === 'failed' || hasValidationError) ? 1 : 0);
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
