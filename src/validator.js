/**
 * Validates a generated CycloneDX BOM against structural requirements.
 * For full JSON Schema validation, the ajv library with an official schema can be used.
 *
 * This module provides both a robust structural validator and an optional schema validator.
 */

/**
 * Validates a Package URL (PURL) according to the Package URL specification format.
 * Checks for the 'pkg:' scheme, valid package type, valid name, and well-formed structure.
 *
 * @param {string} purl - The PURL string to validate.
 * @returns {{ valid: boolean, error?: string }} Validation result with error message if invalid.
 */
export function validatePurl(purl) {
  if (typeof purl !== 'string' || purl.trim() === '') {
    return { valid: false, error: 'PURL must be a non-empty string.' };
  }
  if (!purl.startsWith('pkg:')) {
    return { valid: false, error: `PURL must start with "pkg:", got "${purl}".` };
  }

  const remainder = purl.substring(4);
  if (!remainder || remainder.startsWith('/')) {
    return { valid: false, error: `PURL is missing type in "${purl}".` };
  }

  // Split qualifiers (?) and subpath (#)
  let beforeSubpath = remainder;
  const subpathIndex = beforeSubpath.indexOf('#');
  if (subpathIndex !== -1) {
    beforeSubpath = beforeSubpath.substring(0, subpathIndex);
  }
  let beforeQualifiers = beforeSubpath;
  const qualifierIndex = beforeQualifiers.indexOf('?');
  if (qualifierIndex !== -1) {
    beforeQualifiers = beforeQualifiers.substring(0, qualifierIndex);
  }

  // Split version (@)
  let beforeVersion = beforeQualifiers;
  const atIndex = beforeVersion.lastIndexOf('@');
  if (atIndex !== -1) {
    const version = beforeVersion.substring(atIndex + 1);
    beforeVersion = beforeVersion.substring(0, atIndex);
    if (!version || version.trim() === '') {
      return { valid: false, error: `PURL has empty version after "@" in "${purl}".` };
    }
  }

  // Parts should be "type/namespace/name" or "type/name"
  const parts = beforeVersion.split('/');
  if (parts.length < 2) {
    return { valid: false, error: `PURL must include type and name separated by "/", got "${purl}".` };
  }

  const type = parts[0];
  if (!/^[a-zA-Z0-9_.\+-]+$/.test(type)) {
    return { valid: false, error: `PURL contains invalid type "${type}" in "${purl}".` };
  }

  for (let i = 0; i < parts.length; i++) {
    if (!parts[i] || parts[i].trim() === '') {
      return { valid: false, error: `PURL contains empty segment in "${purl}".` };
    }
  }

  const name = parts[parts.length - 1];
  if (!name || name.trim() === '') {
    return { valid: false, error: `PURL is missing package name in "${purl}".` };
  }

  return { valid: true };
}

/**
 * Performs comprehensive structural validation of a CycloneDX BOM object.
 * Validates top-level fields, metadata, components, dependencies, uniqueness,
 * and graph referential integrity (including dangling edge detection).
 *
 * @param {object} bom - The CycloneDX BOM object to validate.
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateStructure(bom) {
  const errors = [];
  const warnings = [];

  if (!bom || typeof bom !== 'object' || Array.isArray(bom)) {
    errors.push('BOM must be a non-null object.');
    return { valid: false, errors, warnings };
  }

  // 1. Required top-level fields
  if (!bom.bomFormat) {
    errors.push('bomFormat is required and must be "CycloneDX".');
  } else if (bom.bomFormat !== 'CycloneDX') {
    errors.push(`bomFormat must be "CycloneDX", got "${bom.bomFormat}".`);
  }

  if (!bom.specVersion || typeof bom.specVersion !== 'string') {
    errors.push('specVersion is required and must be a string.');
  } else if (!['1.4', '1.5', '1.6', '1.7'].includes(bom.specVersion) && !/^1\.[0-9]+$/.test(bom.specVersion)) {
    errors.push(`specVersion "${bom.specVersion}" is not supported.`);
  }

  if (bom.version === undefined || typeof bom.version !== 'number' || !Number.isInteger(bom.version) || bom.version < 1) {
    errors.push('version is required and must be an integer >= 1.');
  }

  if (!bom.serialNumber || typeof bom.serialNumber !== 'string') {
    errors.push('serialNumber is required and must be a valid UUID URN.');
  } else {
    const uuidPattern = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidPattern.test(bom.serialNumber)) {
      errors.push(`serialNumber must match RFC 4122 URN format, got "${bom.serialNumber}".`);
    }
  }

  // 2. Metadata validation
  let rootBomRef = null;
  const allKnownBomRefs = new Set();

  if (!bom.metadata || typeof bom.metadata !== 'object' || Array.isArray(bom.metadata)) {
    errors.push('metadata is required and must be an object.');
  } else {
    // Timestamp
    if (!bom.metadata.timestamp || typeof bom.metadata.timestamp !== 'string') {
      errors.push('metadata.timestamp is required and must be an ISO-8601 date string.');
    } else {
      const parsedTime = Date.parse(bom.metadata.timestamp);
      if (Number.isNaN(parsedTime) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(bom.metadata.timestamp)) {
        errors.push(`metadata.timestamp must be a valid ISO-8601 date string, got "${bom.metadata.timestamp}".`);
      }
    }

    // Tools
    if (bom.metadata.tools !== undefined) {
      if (bom.metadata.tools === null || typeof bom.metadata.tools !== 'object') {
        errors.push('metadata.tools must be an object or array.');
      } else if (!Array.isArray(bom.metadata.tools) && bom.metadata.tools.components !== undefined && !Array.isArray(bom.metadata.tools.components)) {
        errors.push('metadata.tools.components must be an array.');
      }
    }

    // Root component
    if (!bom.metadata.component || typeof bom.metadata.component !== 'object' || Array.isArray(bom.metadata.component)) {
      errors.push('metadata.component is required and must be an object representing the root component.');
    } else {
      const rootComp = bom.metadata.component;

      if (!rootComp.type || typeof rootComp.type !== 'string' || rootComp.type.trim() === '') {
        errors.push('metadata.component is missing required field "type".');
      }

      if (!rootComp.name || typeof rootComp.name !== 'string' || rootComp.name.trim() === '') {
        errors.push('metadata.component is missing required field "name".');
      }

      if (!rootComp['bom-ref'] || typeof rootComp['bom-ref'] !== 'string' || rootComp['bom-ref'].trim() === '') {
        errors.push('metadata.component is missing required field "bom-ref".');
      } else {
        rootBomRef = rootComp['bom-ref'];
        allKnownBomRefs.add(rootBomRef);
      }

      if (rootComp.purl !== undefined) {
        const purlRes = validatePurl(rootComp.purl);
        if (!purlRes.valid) {
          errors.push(`metadata.component purl is invalid: ${purlRes.error}`);
        }
      }
    }
  }

  // 3. Components validation
  const seenComponentBomRefs = new Set();

  if (bom.components !== undefined) {
    if (!Array.isArray(bom.components)) {
      errors.push('components must be an array.');
    } else {
      for (let i = 0; i < bom.components.length; i++) {
        const comp = bom.components[i];
        if (!comp || typeof comp !== 'object' || Array.isArray(comp)) {
          errors.push(`components[${i}] must be an object.`);
          continue;
        }

        const compLabel = comp.name ? `"${comp.name}"` : `at index ${i}`;

        if (!comp.type || typeof comp.type !== 'string' || comp.type.trim() === '') {
          errors.push(`components[${i}] (${compLabel}) is missing required field "type".`);
        }

        if (!comp.name || typeof comp.name !== 'string' || comp.name.trim() === '') {
          errors.push(`components[${i}] is missing required field "name".`);
        }

        if (comp.version === undefined || comp.version === null || typeof comp.version !== 'string' || comp.version.trim() === '') {
          errors.push(`components[${i}] (${compLabel}) is missing required field "version".`);
        }

        if (comp['bom-ref'] === undefined) {
          errors.push(`components[${i}] (${compLabel}) is missing required field "bom-ref".`);
        } else if (typeof comp['bom-ref'] !== 'string' || comp['bom-ref'].trim() === '') {
          errors.push(`components[${i}] (${compLabel}) has an empty "bom-ref".`);
        } else {
          const ref = comp['bom-ref'];
          if (rootBomRef && ref === rootBomRef) {
            errors.push(`Root component bom-ref collision: component ${compLabel} collides with root component bom-ref "${ref}".`);
          } else if (seenComponentBomRefs.has(ref)) {
            errors.push(`Duplicate bom-ref: "${ref}".`);
          } else {
            seenComponentBomRefs.add(ref);
            allKnownBomRefs.add(ref);
          }
        }

        if (comp.purl !== undefined) {
          const purlRes = validatePurl(comp.purl);
          if (!purlRes.valid) {
            errors.push(`components[${i}] (${compLabel}) purl is invalid: ${purlRes.error}`);
          }
        }

        if (comp.hashes !== undefined) {
          if (!Array.isArray(comp.hashes)) {
            errors.push(`components[${i}] (${compLabel}) hashes must be an array.`);
          } else {
            for (let h = 0; h < comp.hashes.length; h++) {
              const hashObj = comp.hashes[h];
              if (!hashObj || typeof hashObj !== 'object' || Array.isArray(hashObj)) {
                errors.push(`components[${i}] (${compLabel}) hashes[${h}] must be an object.`);
              } else if (!hashObj.alg || typeof hashObj.alg !== 'string' || hashObj.alg.trim() === '') {
                errors.push(`components[${i}] (${compLabel}) hashes[${h}] is missing required field "alg".`);
              } else if (!hashObj.content || typeof hashObj.content !== 'string' || hashObj.content.trim() === '') {
                errors.push(`components[${i}] (${compLabel}) hashes[${h}] is missing required field "content".`);
              }
            }
          }
        }
      }
    }
  }

  // 4. Dependencies validation
  if (bom.dependencies !== undefined) {
    if (!Array.isArray(bom.dependencies)) {
      errors.push('dependencies must be an array.');
    } else {
      const seenDepRefs = new Set();
      let hasRootDepEntry = false;

      for (let i = 0; i < bom.dependencies.length; i++) {
        const dep = bom.dependencies[i];
        if (!dep || typeof dep !== 'object' || Array.isArray(dep)) {
          errors.push(`dependencies[${i}] must be an object.`);
          continue;
        }

        let currentDepRef = null;

        if (dep.ref === undefined) {
          errors.push(`dependencies[${i}] is missing required field "ref".`);
        } else if (typeof dep.ref !== 'string' || dep.ref.trim() === '') {
          errors.push(`dependencies[${i}] has an empty "ref".`);
        } else {
          currentDepRef = dep.ref;
          if (seenDepRefs.has(currentDepRef)) {
            errors.push(`Duplicate dependency entry for ref: "${currentDepRef}".`);
          } else {
            seenDepRefs.add(currentDepRef);
          }

          if (rootBomRef && currentDepRef === rootBomRef) {
            hasRootDepEntry = true;
          }

          if (!allKnownBomRefs.has(currentDepRef)) {
            errors.push(`Dependency entry references nonexistent component ref: "${currentDepRef}".`);
          }
        }

        if (!Array.isArray(dep.dependsOn)) {
          errors.push(`dependencies[${i}] must have a "dependsOn" array.`);
        } else {
          const seenChildRefs = new Set();
          for (let j = 0; j < dep.dependsOn.length; j++) {
            const childRef = dep.dependsOn[j];
            if (typeof childRef !== 'string' || childRef.trim() === '') {
              errors.push(`dependencies[${i}] contains invalid child reference at index ${j}.`);
            } else {
              if (seenChildRefs.has(childRef)) {
                errors.push(`dependencies[${i}] contains duplicate child reference: "${childRef}".`);
              } else {
                seenChildRefs.add(childRef);
              }

              if (!allKnownBomRefs.has(childRef)) {
                const parentLabel = currentDepRef || `entry ${i}`;
                errors.push(`Dangling dependency reference: "${childRef}" in dependsOn for "${parentLabel}" does not exist in BOM components.`);
              }
            }
          }
        }
      }

      if (rootBomRef && !hasRootDepEntry && (bom.dependencies.length > 0 || (Array.isArray(bom.components) && bom.components.length > 0))) {
        errors.push(`Missing dependency entry for root component "${rootBomRef}".`);
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Validates a CycloneDX BOM against a CycloneDX JSON Schema
 * using the ajv JSON Schema validator.
 *
 * @param {object} bom - The CycloneDX BOM object to validate.
 * @param {object} schema - The CycloneDX JSON Schema object.
 * @returns {Promise<{ valid: boolean, errors: Array<object|string> }>}
 */
export async function validateAgainstSchema(bom, schema) {
  try {
    if (!schema || typeof schema !== 'object') {
      return {
        valid: false,
        errors: ['Schema validation failed: schema must be an object.'],
      };
    }

    // Dynamic import of ajv — only needed when schema validation is requested
    const { default: Ajv2020 } = await import('ajv/dist/2020.js');
    const { default: addFormats } = await import('ajv-formats');

    const ajv = new Ajv2020({
      strict: false,
      allErrors: true,
      validateFormats: true,
    });
    addFormats(ajv);

    const validate = ajv.compile(schema);
    const valid = validate(bom);

    return {
      valid,
      errors: valid ? [] : validate.errors.map(e => ({
        path: e.instancePath,
        message: e.message,
        params: e.params,
      })),
    };
  } catch (err) {
    return {
      valid: false,
      errors: [`Schema validation failed: ${err.message}`],
    };
  }
}
