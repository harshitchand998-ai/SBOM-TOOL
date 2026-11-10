/**
 * OSV (Open Source Vulnerabilities) API client.
 * Queries the OSV API to retrieve vulnerability information for npm packages.
 */

const OSV_API_URL = 'https://api.osv.dev/v1/query';
const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Queries the OSV API for vulnerabilities affecting a single package.
 *
 * @param {object} pkg - Package to query.
 * @param {string} pkg.name - Package name (e.g. 'express').
 * @param {string} pkg.version - Installed version (e.g. '4.17.1').
 * @param {string} [pkg.ecosystem='npm'] - Package ecosystem.
 * @returns {Promise<{ package: { name: string, version: string, ecosystem: string }, vulnerabilities: object[] }>}
 */
export async function queryPackage({ name, version, ecosystem = 'npm' }) {
  const body = JSON.stringify({
    version,
    package: { name, ecosystem },
  });

  let response;
  try {
    response = await fetch(OSV_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
  } catch (err) {
    if (err.name === 'TimeoutError') {
      throw new OsvError('REQUEST_TIMEOUT', `OSV API request timed out for ${name}@${version}`);
    }
    throw new OsvError('NETWORK_ERROR', `OSV API request failed for ${name}@${version}: ${err.message}`);
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
 * Individual failures do not fail the entire batch.
 *
 * @param {Array<{ name: string, version: string, ecosystem?: string }>} packages
 * @returns {Promise<Array<{ package: object, vulnerabilities?: object[], error?: { code: string, message: string } }>>}
 */
export async function queryPackages(packages) {
  const results = await Promise.allSettled(
    packages.map(pkg => queryPackage(pkg))
  );

  return results.map((result, i) => {
    if (result.status === 'fulfilled') {
      return result.value;
    }
    const err = result.reason;
    return {
      package: { name: packages[i].name, version: packages[i].version, ecosystem: packages[i].ecosystem || 'npm' },
      vulnerabilities: [],
      error: {
        code: err instanceof OsvError ? err.code : 'UNKNOWN_ERROR',
        message: err.message,
      },
    };
  });
}

/**
 * Extracts relevant fields from a raw OSV vulnerability object.
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
  };
}

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

