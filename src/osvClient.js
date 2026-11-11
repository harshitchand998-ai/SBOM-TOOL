/**
 * OSV (Open Source Vulnerabilities) API client.
 * Queries the OSV API to retrieve vulnerability information for npm packages.
 */

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_CONCURRENCY = 8;

/**
 * Error class for OSV API failures.
 */
export class OsvError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OsvError';
    this.code = code;
  }
}

/**
 * Validates package query input fields.
 *
 * @param {object} pkg - Package descriptor to validate.
 * @throws {OsvError} If input is invalid.
 */
function validatePackageInput(pkg) {
  if (!pkg || typeof pkg !== 'object') {
    throw new OsvError('INVALID_INPUT', 'Package query requires a non-null package object');
  }

  const { name, version, ecosystem = 'npm' } = pkg;

  if (typeof name !== 'string' || name.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package name is required and must be a non-empty string');
  }

  if (typeof version !== 'string' || version.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package version is required and must be a non-empty string');
  }

  if (typeof ecosystem !== 'string' || ecosystem.trim() === '') {
    throw new OsvError('INVALID_INPUT', 'Package ecosystem must be a non-empty string');
  }

  return {
    name: name.trim(),
    version: version.trim(),
    ecosystem: ecosystem.trim(),
  };
}

/**
 * Queries the OSV API for vulnerabilities affecting a single package.
 *
 * @param {object} pkg - Package to query.
 * @param {string} pkg.name - Package name (e.g. 'express').
 * @param {string} pkg.version - Installed version (e.g. '4.17.1').
 * @param {string} [pkg.ecosystem='npm'] - Package ecosystem.
 * @param {object} [options={}] - Query options.
 * @param {number} [options.timeoutMs=10000] - Request timeout in milliseconds.
 * @param {string} [options.apiUrl] - Optional custom OSV API endpoint URL.
 * @returns {Promise<{ package: { name: string, version: string, ecosystem: string }, vulnerabilities: object[] }>}
 */
export async function queryPackage(pkg, options = {}) {
  const validated = validatePackageInput(pkg);
  const { name, version, ecosystem } = validated;

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const apiUrl = options.apiUrl ?? OSV_API_URL;

  const body = JSON.stringify({
    version,
    package: { name, ecosystem },
  });

  let response;
  try {
    response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (err.name === 'TimeoutError') {
      throw new OsvError('REQUEST_TIMEOUT', `OSV API request timed out for ${name}@${version}`);
    }
    throw new OsvError('NETWORK_ERROR', `OSV API request failed for ${name}@${version}: ${err.message}`);
  }

  if (response.status === 429) {
    throw new OsvError('RATE_LIMITED', `OSV API rate limit exceeded (HTTP 429) for ${name}@${version}`);
  }

  if (!response.ok) {
    throw new OsvError('API_ERROR', `OSV API returned HTTP ${response.status} for ${name}@${version}`);
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new OsvError('INVALID_RESPONSE', `OSV API returned invalid JSON for ${name}@${version}`);
  }

  if (typeof data !== 'object' || data === null) {
    throw new OsvError('INVALID_RESPONSE', `OSV API returned unexpected response for ${name}@${version}`);
  }

  const vulns = Array.isArray(data.vulns) ? data.vulns.map(formatVulnerability) : [];

  return {
    package: { name, version, ecosystem },
    vulnerabilities: vulns,
  };
}

/**
 * Queries the OSV API for vulnerabilities affecting multiple packages concurrently.
 * Implements bounded concurrency control to prevent network exhaustion and rate limiting.
 * Individual failures do not fail the entire batch.
 *
 * @param {Array<{ name: string, version: string, ecosystem?: string }>} packages - Packages to query.
 * @param {object} [options={}] - Options (e.g., concurrency, timeoutMs).
 * @returns {Promise<Array<{ package: object, vulnerabilities?: object[], error?: { code: string, message: string } }>>}
 */
export async function queryPackages(packages, options = {}) {
  if (!Array.isArray(packages) || packages.length === 0) {
    return [];
  }

  const concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
  const results = new Array(packages.length);
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < packages.length) {
      const idx = currentIndex++;
      const pkg = packages[idx];

      try {
        const val = await queryPackage(pkg, options);
        results[idx] = {
          status: 'fulfilled',
          value: val,
        };
      } catch (err) {
        results[idx] = {
          status: 'rejected',
          reason: err,
        };
      }
    }
  }

  const workerCount = Math.min(concurrency, packages.length);
  const workers = Array.from({ length: workerCount }, () => worker());
  await Promise.all(workers);

  return results.map((result, i) => {
    const pkg = packages[i];
    const pkgName = pkg?.name || 'unknown';
    const pkgVersion = pkg?.version || 'unknown';
    const pkgEcosystem = pkg?.ecosystem || 'npm';

    if (result.status === 'fulfilled') {
      return result.value;
    }
    const err = result.reason;
    return {
      package: { name: pkgName, version: pkgVersion, ecosystem: pkgEcosystem },
      vulnerabilities: [],
      error: {
        code: err instanceof OsvError ? err.code : 'UNKNOWN_ERROR',
        message: err?.message || 'Unknown error occurred',
      },
    };
  });
}

/**
 * Extracts and normalizes relevant fields from a raw OSV vulnerability object.
 * Preserves all metadata required for accurate vulnerability matching and reporting.
 *
 * @param {object} vuln - Raw vulnerability from OSV API.
 * @returns {object} Formatted vulnerability.
 */
function formatVulnerability(vuln) {
  return {
    id: vuln.id || null,
    summary: vuln.summary || null,
    details: vuln.details || null,
    aliases: Array.isArray(vuln.aliases) ? vuln.aliases : [],
    published: vuln.published || null,
    modified: vuln.modified || null,
    affected: Array.isArray(vuln.affected) ? vuln.affected : [],
    severity: Array.isArray(vuln.severity) ? vuln.severity : [],
    references: Array.isArray(vuln.references) ? vuln.references : [],
    database_specific: vuln.database_specific || null,
    ecosystem_specific: vuln.ecosystem_specific || null,
    schema_version: vuln.schema_version || null,
  };
}
