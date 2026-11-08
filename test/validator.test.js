import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateStructure, validateAgainstSchema, validatePurl } from '../src/validator.js';

/**
 * Creates a valid, minimal CycloneDX 1.7 BOM for testing.
 */
function createValidBom(overrides = {}) {
  const rootRef = 'pkg:npm/my-app@1.0.0';
  const libRef = 'pkg:npm/lodash@4.17.21';

  const base = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
    version: 1,
    metadata: {
      timestamp: '2026-11-08T10:00:00.000Z',
      tools: {
        components: [
          {
            type: 'application',
            name: 'npm-sbom-tool',
            version: '0.1.0',
          },
        ],
      },
      component: {
        type: 'application',
        name: 'my-app',
        version: '1.0.0',
        'bom-ref': rootRef,
        purl: rootRef,
      },
    },
    components: [
      {
        type: 'library',
        name: 'lodash',
        version: '4.17.21',
        'bom-ref': libRef,
        purl: libRef,
      },
    ],
    dependencies: [
      {
        ref: rootRef,
        dependsOn: [libRef],
      },
      {
        ref: libRef,
        dependsOn: [],
      },
    ],
  };

  return { ...base, ...overrides };
}

describe('CycloneDX Validator', () => {
  describe('PURL Validation (validatePurl)', () => {
    it('accepts valid standard npm PURL', () => {
      const res = validatePurl('pkg:npm/lodash@4.17.21');
      assert.equal(res.valid, true);
    });

    it('accepts valid scoped npm PURL with URL-encoded scope', () => {
      const res = validatePurl('pkg:npm/%40babel/core@7.24.0');
      assert.equal(res.valid, true);
    });

    it('accepts valid scoped npm PURL with raw scope', () => {
      const res = validatePurl('pkg:npm/@babel/core@7.24.0');
      assert.equal(res.valid, true);
    });

    it('accepts valid PURL with qualifiers and subpaths', () => {
      const res = validatePurl('pkg:npm/lodash@4.17.21?repository_url=https://github.com/lodash/lodash#packages/lodash');
      assert.equal(res.valid, true);
    });

    it('rejects non-string or empty PURL', () => {
      assert.equal(validatePurl(null).valid, false);
      assert.equal(validatePurl('').valid, false);
      assert.equal(validatePurl('   ').valid, false);
    });

    it('rejects PURL without pkg: scheme', () => {
      const res = validatePurl('http://npm/lodash@4.17.21');
      assert.equal(res.valid, false);
      assert.match(res.error, /must start with "pkg:"/);
    });

    it('rejects PURL with missing type or name', () => {
      const res1 = validatePurl('pkg:npm');
      assert.equal(res1.valid, false);
      const res2 = validatePurl('pkg:/lodash@1.0.0');
      assert.equal(res2.valid, false);
    });

    it('rejects PURL with empty version when @ is present', () => {
      const res = validatePurl('pkg:npm/lodash@');
      assert.equal(res.valid, false);
      assert.match(res.error, /empty version/);
    });
  });

  describe('Valid BOM Scenarios', () => {
    it('1. Valid basic CycloneDX BOM passes validation', () => {
      const bom = createValidBom();
      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('2. Valid BOM with third-party dependencies', () => {
      const bom = createValidBom();
      const depRef = 'pkg:npm/dep-a@1.0.0';
      bom.components.push({
        type: 'library',
        name: 'dep-a',
        version: '1.0.0',
        'bom-ref': depRef,
        purl: depRef,
      });
      bom.dependencies[0].dependsOn.push(depRef);
      bom.dependencies.push({ ref: depRef, dependsOn: [] });

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('3. Valid BOM with first-party workspace components', () => {
      const bom = createValidBom();
      const wsRef = 'pkg:npm/my-workspace-pkg@1.0.0#packages/pkg-a';
      bom.components.push({
        type: 'library',
        name: 'my-workspace-pkg',
        version: '1.0.0',
        'bom-ref': wsRef,
        purl: 'pkg:npm/my-workspace-pkg@1.0.0',
      });
      bom.dependencies[0].dependsOn.push(wsRef);
      bom.dependencies.push({ ref: wsRef, dependsOn: [] });

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('4. Valid BOM with multiple versions of the same package', () => {
      const bom = createValidBom();
      const v1Ref = 'pkg:npm/shared-lib@1.0.0';
      const v2Ref = 'pkg:npm/shared-lib@2.0.0';
      bom.components.push(
        {
          type: 'library',
          name: 'shared-lib',
          version: '1.0.0',
          'bom-ref': v1Ref,
          purl: v1Ref,
        },
        {
          type: 'library',
          name: 'shared-lib',
          version: '2.0.0',
          'bom-ref': v2Ref,
          purl: v2Ref,
        }
      );
      bom.dependencies[0].dependsOn.push(v1Ref, v2Ref);
      bom.dependencies.push({ ref: v1Ref, dependsOn: [] }, { ref: v2Ref, dependsOn: [] });

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('5. Valid BOM with no dependencies', () => {
      const rootRef = 'pkg:npm/zero-dep-app@1.0.0';
      const bom = createValidBom({
        metadata: {
          timestamp: '2026-11-08T10:00:00.000Z',
          component: {
            type: 'application',
            name: 'zero-dep-app',
            version: '1.0.0',
            'bom-ref': rootRef,
          },
        },
        components: [],
        dependencies: [
          {
            ref: rootRef,
            dependsOn: [],
          },
        ],
      });

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('6. Valid BOM with an empty component array', () => {
      const rootRef = 'pkg:npm/empty-components@1.0.0';
      const bom = createValidBom({
        metadata: {
          timestamp: '2026-11-08T10:00:00.000Z',
          component: {
            type: 'application',
            name: 'empty-components',
            version: '1.0.0',
            'bom-ref': rootRef,
          },
        },
        components: [],
        dependencies: [{ ref: rootRef, dependsOn: [] }],
      });

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });
  });

  describe('Invalid Metadata Scenarios', () => {
    it('7. Missing bomFormat', () => {
      const bom = createValidBom();
      delete bom.bomFormat;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('bomFormat is required')));
    });

    it('8. Incorrect bomFormat', () => {
      const bom = createValidBom({ bomFormat: 'SPDX' });
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('bomFormat must be "CycloneDX"')));
    });

    it('9. Missing specVersion', () => {
      const bom = createValidBom();
      delete bom.specVersion;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('specVersion is required')));
    });

    it('10. Invalid BOM version', () => {
      const bomZero = createValidBom({ version: 0 });
      assert.equal(validateStructure(bomZero).valid, false);

      const bomNegative = createValidBom({ version: -1 });
      assert.equal(validateStructure(bomNegative).valid, false);

      const bomFloat = createValidBom({ version: 1.5 });
      assert.equal(validateStructure(bomFloat).valid, false);

      const bomStr = createValidBom({ version: '1' });
      assert.equal(validateStructure(bomStr).valid, false);
    });

    it('11. Missing serial number', () => {
      const bom = createValidBom();
      delete bom.serialNumber;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('serialNumber is required')));
    });

    it('12. Invalid UUID format in serial number', () => {
      const bom = createValidBom({ serialNumber: 'urn:uuid:invalid-uuid' });
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('serialNumber must match RFC 4122 URN format')));
    });

    it('13. Missing metadata', () => {
      const bom = createValidBom();
      delete bom.metadata;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('metadata is required')));
    });

    it('14. Missing metadata timestamp', () => {
      const bom = createValidBom();
      delete bom.metadata.timestamp;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('metadata.timestamp is required')));
    });

    it('15. Invalid metadata timestamp', () => {
      const bom = createValidBom();
      bom.metadata.timestamp = 'invalid-timestamp-date';
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('metadata.timestamp must be a valid ISO-8601 date string')));
    });

    it('16. Missing root component', () => {
      const bom = createValidBom();
      delete bom.metadata.component;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('metadata.component is required')));
    });
  });

  describe('Invalid Component Scenarios', () => {
    it('17. Missing component name', () => {
      const bom = createValidBom();
      delete bom.components[0].name;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('missing required field "name"')));
    });

    it('18. Missing component type', () => {
      const bom = createValidBom();
      delete bom.components[0].type;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('missing required field "type"')));
    });

    it('19. Missing component bom-ref', () => {
      const bom = createValidBom();
      delete bom.components[0]['bom-ref'];
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('missing required field "bom-ref"')));
    });

    it('20. Empty component bom-ref', () => {
      const bom = createValidBom();
      bom.components[0]['bom-ref'] = '   ';
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('has an empty "bom-ref"')));
    });

    it('21. Missing required version', () => {
      const bom = createValidBom();
      delete bom.components[0].version;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('missing required field "version"')));
    });

    it('22. Invalid PURL on component', () => {
      const bom = createValidBom();
      bom.components[0].purl = 'not-a-valid-purl';
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('purl is invalid')));
    });

    it('23. Duplicate component bom-ref', () => {
      const bom = createValidBom();
      const dupRef = 'pkg:npm/duplicate@1.0.0';
      bom.components.push(
        {
          type: 'library',
          name: 'lib-a',
          version: '1.0.0',
          'bom-ref': dupRef,
        },
        {
          type: 'library',
          name: 'lib-b',
          version: '1.0.0',
          'bom-ref': dupRef,
        }
      );
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes(`Duplicate bom-ref: "${dupRef}"`)));
    });

    it('24. Root component bom-ref collision with a component', () => {
      const bom = createValidBom();
      const rootRef = bom.metadata.component['bom-ref'];
      bom.components.push({
        type: 'library',
        name: 'sneaky-lib',
        version: '1.0.0',
        'bom-ref': rootRef, // collides with root component
      });
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('Root component bom-ref collision')));
    });
  });

  describe('Invalid Dependency Scenarios', () => {
    it('25. Missing dependency reference', () => {
      const bom = createValidBom();
      delete bom.dependencies[0].ref;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('missing required field "ref"')));
    });

    it('26. Empty dependency reference', () => {
      const bom = createValidBom();
      bom.dependencies[0].ref = '   ';
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('has an empty "ref"')));
    });

    it('27. Missing dependsOn array', () => {
      const bom = createValidBom();
      delete bom.dependencies[0].dependsOn;
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('must have a "dependsOn" array')));
    });

    it('28. Dependency reference pointing to a nonexistent component', () => {
      const bom = createValidBom();
      bom.dependencies.push({
        ref: 'pkg:npm/phantom-component@1.0.0',
        dependsOn: [],
      });
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('references nonexistent component ref')));
    });

    it('29. dependsOn pointing to a nonexistent component (dangling edge)', () => {
      const bom = createValidBom();
      bom.dependencies[0].dependsOn.push('pkg:npm/ghost-dep@9.9.9');
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('Dangling dependency reference')));
    });

    it('30. Missing root dependency entry when required', () => {
      const bom = createValidBom();
      // Remove root dependency entry from dependencies
      bom.dependencies = bom.dependencies.filter(d => d.ref !== bom.metadata.component['bom-ref']);
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('Missing dependency entry for root component')));
    });

    it('31. Malformed dependency entry (non-object or null)', () => {
      const bom = createValidBom();
      bom.dependencies.push(null);
      bom.dependencies.push('string-dependency');
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('must be an object')));
    });

    it('32. Duplicate dependency references (duplicate entry and duplicate in dependsOn)', () => {
      const bom = createValidBom();
      const libRef = bom.components[0]['bom-ref'];

      // Duplicate child reference in dependsOn
      bom.dependencies[0].dependsOn.push(libRef);

      // Duplicate dependency entry
      bom.dependencies.push({
        ref: libRef,
        dependsOn: [],
      });

      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('duplicate child reference')));
      assert.ok(res.errors.some(e => e.includes('Duplicate dependency entry')));
    });
  });

  describe('Robustness Scenarios', () => {
    it('33. Null BOM input', () => {
      const res = validateStructure(null);
      assert.equal(res.valid, false);
      assert.equal(res.errors[0], 'BOM must be a non-null object.');
    });

    it('34. Non-object BOM input', () => {
      assert.equal(validateStructure(undefined).valid, false);
      assert.equal(validateStructure('string-bom').valid, false);
      assert.equal(validateStructure(12345).valid, false);
      assert.equal(validateStructure(true).valid, false);
      assert.equal(validateStructure([]).valid, false);
    });

    it('35. Malformed component values (null/primitive in components)', () => {
      const bom = createValidBom();
      bom.components.push(null);
      bom.components.push('not-an-object');
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('must be an object')));
    });

    it('36. Malformed dependency values (null/primitive child in dependsOn)', () => {
      const bom = createValidBom();
      bom.dependencies[0].dependsOn.push(null);
      bom.dependencies[0].dependsOn.push(123);
      const res = validateStructure(bom);
      assert.equal(res.valid, false);
      assert.ok(res.errors.some(e => e.includes('invalid child reference')));
    });

    it('37. Empty arrays handled gracefully', () => {
      const rootRef = 'pkg:npm/standalone@1.0.0';
      const bom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.7',
        serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
        version: 1,
        metadata: {
          timestamp: '2026-11-08T10:00:00.000Z',
          component: {
            type: 'application',
            name: 'standalone',
            version: '1.0.0',
            'bom-ref': rootRef,
          },
        },
        components: [],
        dependencies: [],
      };

      const res = validateStructure(bom);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('38. Unexpected field types for components and dependencies', () => {
      const bom1 = createValidBom({ components: 'not-an-array' });
      const res1 = validateStructure(bom1);
      assert.equal(res1.valid, false);
      assert.ok(res1.errors.some(e => e.includes('components must be an array')));

      const bom2 = createValidBom({ dependencies: 42 });
      const res2 = validateStructure(bom2);
      assert.equal(res2.valid, false);
      assert.ok(res2.errors.some(e => e.includes('dependencies must be an array')));
    });
  });

  describe('Optional Schema Validation (validateAgainstSchema)', () => {
    it('returns error when schema is missing or invalid', async () => {
      const bom = createValidBom();
      const res = await validateAgainstSchema(bom, null);
      assert.equal(res.valid, false);
      assert.ok(res.errors[0].includes('schema must be an object'));
    });

    it('validates successfully against a valid custom schema', async () => {
      const bom = createValidBom();
      const simpleSchema = {
        type: 'object',
        required: ['bomFormat', 'specVersion', 'version'],
        properties: {
          bomFormat: { const: 'CycloneDX' },
          specVersion: { type: 'string' },
          version: { type: 'integer', minimum: 1 },
        },
      };

      const res = await validateAgainstSchema(bom, simpleSchema);
      assert.equal(res.valid, true);
      assert.equal(res.errors.length, 0);
    });

    it('returns formatted schema error when BOM violates schema', async () => {
      const bom = createValidBom({ bomFormat: 'InvalidFormat' });
      const simpleSchema = {
        type: 'object',
        required: ['bomFormat'],
        properties: {
          bomFormat: { const: 'CycloneDX' },
        },
      };

      const res = await validateAgainstSchema(bom, simpleSchema);
      assert.equal(res.valid, false);
      assert.ok(res.errors.length > 0);
    });
  });
});
