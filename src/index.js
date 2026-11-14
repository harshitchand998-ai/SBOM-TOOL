export {
  runEngine,
  generateSbom,
  executeScan,
  executeSbom,
  executeAudit,
  default,
} from './engine/index.js';
export {
  generateReport,
  generateReportFiles,
  buildCombinedReport,
  writeMultiFileOutput,
  computeSeverityCounts,
} from './reportGenerator.js';
export { scanProject, scanProjectSync } from './scanner/index.js';
export { generateCycloneDX } from './cyclonedxGenerator.js';
export { validateStructure, validateAgainstSchema, validatePurl } from './validator.js';
export {
  discoverFirstPartyComponents,
  discoverFirstPartyComponentsSync,
  discoverWorkspaces,
  discoverWorkspacesSync,
  classifyComponent,
  classifyComponents,
  isVersionCompatible,
} from './workspaceDiscovery.js';
export { queryPackage, queryPackages, OsvError } from './osvClient.js';
export {
  matchVulnerabilities,
  isVersionAffected,
  evaluateVersionAgainstRange,
  parseSemver,
  compareSemver,
} from './vulnerabilityMatcher.js';
export {
  generateFindings,
  createFindings,
  deduplicateFindings,
  extractSeverity,
  extractFixedVersions,
} from './vulnerabilityFindings.js';
export {
  checkVulnerabilities,
  extractEligiblePackages,
} from './vulnerabilityChecker.js';
export {
  detectAnomalies,
  summarizeAnomalies,
  parsePurl,
  createAnomalyExplanation,
  AnomalyType,
  AnomalySeverity,
} from './anomalyDetector.js';
export {
  compareInventories,
  ComparisonStatus,
  ChangeType,
} from './dependencyComparison.js';
