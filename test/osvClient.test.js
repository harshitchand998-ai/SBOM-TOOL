import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { queryPackage, queryPackages, OsvError } from '../src/osvClient.js';

// Helper to create a mock Response
function mockResponse(body, { status = 200, ok = true } = {}) {
  return {
    ok,
    status,
    json: async () => body,
  };
}

// Helper to create a mock Response with invalid JSON
function mockInvalidJsonResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError('Unexpected token'); },
  };
}

describe('osvClient', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('queryPackage', () => {
    it('returns empty vulnerabilities for a clean package', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({ vulns: [] }));

      const result = await queryPackage({ name: 'express', version: '4.18.2' });

      assert.deepEqual(result.package, { name: 'express', version: '4.18.2', ecosystem: 'npm' });
      assert.deepEqual(result.vulnerabilities, []);

      // Verify the request was made correctly
      const call = globalThis.fetch.mock.calls[0];
      assert.equal(call.arguments[0], 'https://api.osv.dev/v1/query');
      const body = JSON.parse(call.arguments[1].body);
      assert.equal(body.package.name, 'express');
      assert.equal(body.package.ecosystem, 'npm');
      assert.equal(body.version, '4.18.2');
    });

    it('returns empty vulnerabilities when API returns no vulns key', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({}));

      const result = await queryPackage({ name: 'safe-pkg', version: '1.0.0' });

      assert.deepEqual(result.vulnerabilities, []);
    });

    it('returns a single vulnerability with all fields', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        vulns: [{
          id: 'GHSA-1234-5678-abcd',
          summary: 'Prototype pollution in lodash',
          details: 'Detailed description here.',
          aliases: ['CVE-2021-23337'],
          published: '2021-02-19T00:00:00Z',
          modified: '2021-03-01T00:00:00Z',
          affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [] }],
          severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
          references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }],
        }],
      }));

      const result = await queryPackage({ name: 'lodash', version: '4.17.20' });

      assert.equal(result.vulnerabilities.length, 1);
      const vuln = result.vulnerabilities[0];
      assert.equal(vuln.id, 'GHSA-1234-5678-abcd');
      assert.equal(vuln.summary, 'Prototype pollution in lodash');
      assert.equal(vuln.details, 'Detailed description here.');
      assert.deepEqual(vuln.aliases, ['CVE-2021-23337']);
      assert.equal(vuln.published, '2021-02-19T00:00:00Z');
      assert.equal(vuln.modified, '2021-03-01T00:00:00Z');
      assert.equal(vuln.affected.length, 1);
      assert.equal(vuln.severity.length, 1);
      assert.equal(vuln.references.length, 1);
    });

    it('returns multiple vulnerabilities', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse({
        vulns: [
          { id: 'GHSA-aaaa', summary: 'Vuln 1' },
          { id: 'GHSA-bbbb', summary: 'Vuln 2' },
          { id: 'GHSA-cccc', summary: 'Vuln 3' },
        ],
      }));

      const result = await queryPackage({ name: 'vulnerable-pkg', version: '1.0.0' });

      assert.equal(result.vulnerabilities.length, 3);
      assert.equal(result.vulnerabilities[0].id, 'GHSA-aaaa');
      assert.equal(result.vulnerabilities[1].id, 'GHSA-bbbb');
      assert.equal(result.vulnerabilities[2].id, 'GHSA-cccc');
      // Missing fields default to null or empty arrays
      assert.equal(result.vulnerabilities[0].details, null);
      assert.deepEqual(result.vulnerabilities[0].aliases, []);
      assert.deepEqual(result.vulnerabilities[0].severity, []);
    });

    it('throws NETWORK_ERROR on fetch failure', async () => {
      globalThis.fetch = mock.fn(async () => { throw new TypeError('fetch failed'); });

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'NETWORK_ERROR');
          assert.ok(err.message.includes('pkg@1.0.0'));
          return true;
        }
      );
    });

    it('throws REQUEST_TIMEOUT on timeout', async () => {
      const timeoutErr = new DOMException('The operation was aborted due to timeout', 'TimeoutError');
      globalThis.fetch = mock.fn(async () => { throw timeoutErr; });

      await assert.rejects(
        () => queryPackage({ name: 'slow-pkg', version: '2.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'REQUEST_TIMEOUT');
          assert.ok(err.message.includes('slow-pkg@2.0.0'));
          return true;
        }
      );
    });

    it('throws API_ERROR on non-200 response', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse(null, { status: 500, ok: false }));

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'API_ERROR');
          assert.ok(err.message.includes('500'));
          return true;
        }
      );
    });

    it('throws INVALID_RESPONSE on malformed JSON', async () => {
      globalThis.fetch = mock.fn(async () => mockInvalidJsonResponse());

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_RESPONSE');
          return true;
        }
      );
    });

    it('throws INVALID_RESPONSE when API returns non-object', async () => {
      globalThis.fetch = mock.fn(async () => mockResponse('not an object'));

      await assert.rejects(
        () => queryPackage({ name: 'pkg', version: '1.0.0' }),
        (err) => {
          assert.ok(err instanceof OsvError);
          assert.equal(err.code, 'INVALID_RESPONSE');
          return true;
        }
      );
    });
  });

  describe('queryPackages', () => {
    it('queries multiple packages concurrently', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.package.name === 'lodash') {
          return mockResponse({ vulns: [{ id: 'GHSA-lodash', summary: 'Lodash vuln' }] });
        }
        return mockResponse({ vulns: [] });
      });

      const results = await queryPackages([
        { name: 'lodash', version: '4.17.20' },
        { name: 'express', version: '4.18.2' },
      ]);

      assert.equal(results.length, 2);
      assert.equal(results[0].vulnerabilities.length, 1);
      assert.equal(results[0].vulnerabilities[0].id, 'GHSA-lodash');
      assert.equal(results[1].vulnerabilities.length, 0);
      assert.equal(results[0].error, undefined);
      assert.equal(results[1].error, undefined);
    });

    it('handles individual failures without failing the batch', async () => {
      globalThis.fetch = mock.fn(async (_url, opts) => {
        const body = JSON.parse(opts.body);
        if (body.package.name === 'fail-pkg') {
          throw new TypeError('fetch failed');
        }
        return mockResponse({ vulns: [] });
      });

      const results = await queryPackages([
        { name: 'good-pkg', version: '1.0.0' },
        { name: 'fail-pkg', version: '2.0.0' },
      ]);

      assert.equal(results.length, 2);
      // First package succeeds
      assert.equal(results[0].error, undefined);
      assert.deepEqual(results[0].vulnerabilities, []);
      // Second package has error but doesn't throw
      assert.ok(results[1].error);
      assert.equal(results[1].error.code, 'NETWORK_ERROR');
      assert.deepEqual(results[1].package, { name: 'fail-pkg', version: '2.0.0', ecosystem: 'npm' });
      assert.deepEqual(results[1].vulnerabilities, []);
    });

    it('returns empty array for empty input', async () => {
      const results = await queryPackages([]);
      assert.deepEqual(results, []);
    });
  });
});

