/**
 * Dependency Comparison Module
 *
 * Compares two SBOM inventories (previous vs current) to identify added,
 * removed, changed (upgraded, downgraded, metadata-changed, version-changed),
 * and unchanged dependencies without mutating the inputs.
 */

import { parseSemver, compareSemver } from './vulnerabilityMatcher.js';
import { parsePurl } from './anomalyDetector.js';

const STRICT_SEMVER_RE = /^[=vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Safely deep-clones JSON-compatible metadata values so comparison outputs
 * never alias mutable arrays or objects inside caller SBOM inputs.
 *
 * @param {any} val
 * @returns {any}
 */
function cloneMetadata(val) {
  if (val === null || val === undefined || typeof val !== 'object') {
    return val;
  }
  try {
    return structuredClone(val);
  } catch {
    return JSON.parse(JSON.stringify(val));
  }
}

/**
 * Overall status values for inventory comparison.
 */
export const ComparisonStatus = Object.freeze({
  COMPLETED: 'completed',
  FAILED: 'failed',
});

/**
 * Classification values for component changes between inventories.
 */
export const ChangeType = Object.freeze({
  ADDED: 'added',
  REMOVED: 'removed',
  UPGRADE: 'upgrade',
  DOWNGRADE: 'downgrade',
  METADATA_CHANGED: 'metadata-changed',
  VERSION_CHANGED: 'version-changed',
  UNCHANGED: 'unchanged',
});

/**
 * Extracts and validates the component list from an SBOM inventory object.
 * Supports standard CycloneDX BOMs, minimal BOM-like objects with `components`,
 * and internal scanner result objects (`scanResult`).
 *
 * @param {any} input - SBOM inventory input.
 * @param {'previous' | 'current'} label - Label for diagnostic messages.
 * @param {object} [options={}] - Comparison options.
 * @returns {{
 *   valid: boolean,
 *   components: Array<object>,
 *   error: { code: string, target: string, message: string } | null
 * }}
 */
function extractInventory(input, label, options = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {
      valid: false,
      components: [],
      error: {
        code: 'INVALID_SBOM',
        target: label,
        message: `Invalid ${label} SBOM: expected a non-null SBOM object.`,
      },
    };
  }

  // Case 1: Internal scanResult object
  if (input.bomFormat !== 'CycloneDX' && (input.status !== undefined || input.dependencyEdges !== undefined || input.components instanceof Map)) {
    if (input.status === 'failed') {
      return {
        valid: false,
        components: [],
        error: {
          code: 'FAILED_SCAN_SBOM',
          target: label,
          message: `Cannot compare ${label} SBOM from a failed scan result.`,
        },
      };
    }

    if (input.bom && typeof input.bom === 'object' && Array.isArray(input.bom.components)) {
      return extractInventory(input.bom, label, options);
    }

    let rawList = [];
    if (input.components instanceof Map) {
      rawList = Array.from(input.components.values());
    } else if (Array.isArray(input.components)) {
      rawList = input.components;
    } else if (input.components !== undefined) {
      return {
        valid: false,
        components: [],
        error: {
          code: 'MALFORMED_COMPONENTS',
          target: label,
          message: `Invalid ${label} SBOM: "components" must be an array or Map.`,
        },
      };
    }

    const filtered = options.includeRoot === true
      ? rawList
      : rawList.filter(c => !c || typeof c !== 'object' || !c.isRoot);

    return { valid: true, components: filtered, error: null };
  }

  // Case 2: CycloneDX BOM or BOM-like container
  const hasCdxMarker = input.bomFormat === 'CycloneDX' || (input.metadata && typeof input.metadata === 'object');
  const hasComponentsProp = Object.prototype.hasOwnProperty.call(input, 'components');

  if (!hasCdxMarker && !hasComponentsProp) {
    return {
      valid: false,
      components: [],
      error: {
        code: 'INVALID_SBOM',
        target: label,
        message: `Invalid ${label} SBOM: missing "bomFormat", "metadata", or "components" array.`,
      },
    };
  }

  if (hasComponentsProp && !Array.isArray(input.components)) {
    return {
      valid: false,
      components: [],
      error: {
        code: 'MALFORMED_COMPONENTS',
        target: label,
        message: `Invalid ${label} SBOM: "components" must be an array.`,
      },
    };
  }

  const components = Array.isArray(input.components) ? input.components : [];
  return { valid: true, components, error: null };
}

/**
 * Normalizes a component entry and resolves its canonical package identity.
 *
 * Matching strategy:
 * 1. Prefer parsed PURL (`type` + `fullName`) when present and syntactically valid.
 * 2. Fall back to component metadata (`ecosystem` defaulting to 'npm' + `group/name` or `name`).
 * 3. Returns `identity: null` if neither yields a valid package name.
 *
 * @param {any} comp - Raw component object.
 * @param {number} index - Original index in components array.
 * @param {'previous' | 'current'} label - Inventory label.
 * @returns {{
 *   valid: boolean,
 *   identity: string | null,
 *   name: string | null,
 *   ecosystem: string,
 *   version: string | null,
 *   purl: string | null,
 *   bomRef: string | null,
 *   type: string,
 *   isFirstParty: boolean,
 *   snapshot: object | null,
 *   warnings: Array<{ code: string, target: string, source: string, message: string }>
 * }}
 */
function normalizeComponent(comp, index, label) {
  const source = `${label}.components[${index}]`;
  const warnings = [];

  if (!comp || typeof comp !== 'object' || Array.isArray(comp)) {
    warnings.push({
      code: 'MALFORMED_COMPONENT',
      target: label,
      source,
      message: `Malformed component entry at ${source}; skipping comparison for this entry.`,
    });
    return {
      valid: false,
      identity: null,
      name: null,
      ecosystem: 'unknown',
      version: null,
      purl: null,
      bomRef: null,
      type: 'library',
      isFirstParty: false,
      snapshot: null,
      warnings,
    };
  }

  const rawPurl = typeof comp.purl === 'string' && comp.purl.trim() !== '' ? comp.purl.trim() : null;
  const parsedPurl = rawPurl ? parsePurl(rawPurl) : null;

  if (rawPurl && !parsedPurl) {
    warnings.push({
      code: 'INVALID_PURL',
      target: label,
      source,
      message: `Invalid PURL "${rawPurl}" at ${source}; falling back to component metadata for matching.`,
    });
  }

  const rawName = typeof comp.name === 'string' && comp.name.trim() !== '' ? comp.name.trim() : null;
  const rawGroup = typeof comp.group === 'string' && comp.group.trim() !== '' ? comp.group.trim() : null;
  const fallbackFullName = rawName && rawGroup && !rawName.includes('/')
    ? `${rawGroup}/${rawName}`
    : rawName;

  const rawVersion = typeof comp.version === 'string' && comp.version.trim() !== '' ? comp.version.trim() : null;
  const bomRefVal = comp['bom-ref'] || comp.bomRef;
  const bomRef = typeof bomRefVal === 'string' && bomRefVal.trim() !== '' ? bomRefVal.trim() : null;
  const compType = typeof comp.type === 'string' && comp.type.trim() !== '' ? comp.type.trim().toLowerCase() : 'library';
  const isFirstParty = Boolean(comp.isFirstParty) || comp.dependencyType === 'workspace' || comp.classification === 'first-party';

  // Prefer valid PURL for ecosystem and package name; otherwise fall back to component fields.
  // Do NOT silently assume 'npm' when neither PURL nor ecosystem is specified.
  const ecosystem = parsedPurl
    ? parsedPurl.type
    : (typeof comp.ecosystem === 'string' && comp.ecosystem.trim() !== '' ? comp.ecosystem.trim().toLowerCase() : 'unknown');

  const resolvedName = parsedPurl ? parsedPurl.fullName : fallbackFullName;
  const resolvedVersion = rawVersion || (parsedPurl?.version ?? null);

  if (!resolvedName) {
    warnings.push({
      code: 'UNRESOLVABLE_COMPONENT_IDENTITY',
      target: label,
      source,
      message: `Component at ${source} lacks both a valid PURL and a valid package name; cannot determine identity.`,
    });
    return {
      valid: false,
      identity: null,
      name: null,
      ecosystem,
      version: resolvedVersion,
      purl: rawPurl,
      bomRef,
      type: compType,
      isFirstParty,
      snapshot: null,
      warnings,
    };
  }

  // Canonical versionless package identity allows upgrades/downgrades to match the same package
  const identity = `${ecosystem}:${resolvedName}`;

  const snapshot = {
    name: rawName || resolvedName,
    version: resolvedVersion,
    ecosystem,
    type: compType,
    purl: rawPurl,
    bomRef,
    isFirstParty,
  };

  if (comp.hashes !== undefined) {
    snapshot.hashes = cloneMetadata(comp.hashes);
  }
  if (comp.externalReferences !== undefined) {
    snapshot.externalReferences = cloneMetadata(comp.externalReferences);
  }
  if (comp.licenses !== undefined) {
    snapshot.licenses = cloneMetadata(comp.licenses);
  }
  if (comp.properties !== undefined) {
    snapshot.properties = cloneMetadata(comp.properties);
  }
  if (comp.description !== undefined) {
    snapshot.description = comp.description;
  }
  if (comp.dependencyType !== undefined) {
    snapshot.dependencyType = comp.dependencyType;
  }

  return {
    valid: true,
    identity,
    name: resolvedName,
    ecosystem,
    version: resolvedVersion,
    purl: rawPurl,
    bomRef,
    type: compType,
    isFirstParty,
    snapshot,
    raw: comp,
    source,
    warnings,
  };
}

/**
 * Recursively canonicalizes values into a stable JSON string for equality comparison.
 *
 * @param {any} val
 * @returns {string}
 */
function stableSerialize(val) {
  if (val === null || val === undefined) return 'null';
  if (typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) {
    return `[${val.map(stableSerialize).sort().join(',')}]`;
  }
  const keys = Object.keys(val).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableSerialize(val[k])}`).join(',')}}`;
}

/**
 * Compares metadata fields between two normalized component entries.
 *
 * @param {object} prev
 * @param {object} curr
 * @returns {string[]} List of metadata field names that differ.
 */
function detectChangedMetadataFields(prev, curr) {
  const changed = [];

  if (prev.type !== curr.type) changed.push('type');
  if (prev.ecosystem !== curr.ecosystem) changed.push('ecosystem');
  if (prev.isFirstParty !== curr.isFirstParty) changed.push('isFirstParty');
  if (prev.purl !== curr.purl) changed.push('purl');
  if (prev.bomRef !== curr.bomRef) changed.push('bomRef');

  const optionalFields = ['hashes', 'externalReferences', 'licenses', 'properties', 'description', 'dependencyType'];
  for (const field of optionalFields) {
    const prevVal = prev.raw[field];
    const currVal = curr.raw[field];
    if (prevVal === undefined && currVal === undefined) continue;
    if (stableSerialize(prevVal) !== stableSerialize(currVal)) {
      changed.push(field);
    }
  }

  return changed;
}

/**
 * Compares versions and metadata of a matched component pair.
 * Uses existing SemVer utilities when both versions conform to SemVer 2.0.0.
 *
 * @param {object} prev - Normalized previous component.
 * @param {object} curr - Normalized current component.
 * @returns {{
 *   status: 'unchanged' | 'changed',
 *   changeType: string,
 *   changedFields: string[],
 *   explanation: string,
 *   warnings: Array<object>
 * }}
 */
function classifyComponentPair(prev, curr) {
  const warnings = [];
  const metaChanges = detectChangedMetadataFields(prev, curr);
  const prevVer = prev.version;
  const currVer = curr.version;

  // Case A: Both versions missing
  if (!prevVer && !currVer) {
    if (metaChanges.length === 0) {
      return {
        status: 'unchanged',
        changeType: ChangeType.UNCHANGED,
        changedFields: [],
        explanation: `${curr.name} remained unchanged (version unspecified).`,
        warnings,
      };
    }
    return {
      status: 'changed',
      changeType: ChangeType.METADATA_CHANGED,
      changedFields: metaChanges,
      explanation: `Metadata changed for ${curr.name} (${metaChanges.join(', ')}).`,
      warnings,
    };
  }

  // Case B: One version missing, one present -> cannot establish upgrade or downgrade
  if (!prevVer || !currVer) {
    const changedFields = ['version', ...metaChanges];
    warnings.push({
      code: 'NON_COMPARABLE_VERSIONS',
      target: 'comparison',
      source: curr.identity,
      message: `Cannot classify upgrade/downgrade for ${curr.name}: missing version in ${!prevVer ? 'previous' : 'current'} SBOM.`,
    });
    return {
      status: 'changed',
      changeType: ChangeType.VERSION_CHANGED,
      changedFields,
      explanation: `Version information changed for ${curr.name} from ${prevVer ?? 'unspecified'} to ${currVer ?? 'unspecified'}.`,
      warnings,
    };
  }

  // Case C: Both versions present — check exact string equality first
  if (prevVer === currVer) {
    if (metaChanges.length === 0) {
      return {
        status: 'unchanged',
        changeType: ChangeType.UNCHANGED,
        changedFields: [],
        explanation: `${curr.name}@${currVer} remained unchanged.`,
        warnings,
      };
    }
    return {
      status: 'changed',
      changeType: ChangeType.METADATA_CHANGED,
      changedFields: metaChanges,
      explanation: `Metadata changed for ${curr.name}@${currVer} (${metaChanges.join(', ')}).`,
      warnings,
    };
  }

  // Case D: Version strings differ — evaluate via SemVer 2.0.0 when npm, or strict 3-part SemVer when unknown
  const isNpmPair = prev.ecosystem === 'npm' && curr.ecosystem === 'npm';
  const hasUnknownEco = prev.ecosystem === 'unknown' || curr.ecosystem === 'unknown';
  const isUnknownBridgeNpm = hasUnknownEco && (prev.ecosystem === 'npm' || curr.ecosystem === 'npm' || (prev.ecosystem === 'unknown' && curr.ecosystem === 'unknown'));
  const allowSemver = isNpmPair || (isUnknownBridgeNpm && STRICT_SEMVER_RE.test(prevVer) && STRICT_SEMVER_RE.test(currVer));

  const parsedPrev = allowSemver ? parseSemver(prevVer) : null;
  const parsedCurr = allowSemver ? parseSemver(currVer) : null;

  if (parsedPrev && parsedCurr) {
    const cmp = compareSemver(prevVer, currVer);
    const changedFields = ['version', ...metaChanges];

    if (cmp < 0) {
      return {
        status: 'changed',
        changeType: ChangeType.UPGRADE,
        changedFields,
        explanation: `Upgraded ${curr.name} from ${prevVer} to ${currVer}.`,
        warnings,
      };
    }
    if (cmp > 0) {
      return {
        status: 'changed',
        changeType: ChangeType.DOWNGRADE,
        changedFields,
        explanation: `Downgraded ${curr.name} from ${prevVer} to ${currVer}.`,
        warnings,
      };
    }

    // Semantically equal SemVer (e.g. build metadata or 'v' prefix normalization difference)
    return {
      status: 'changed',
      changeType: ChangeType.METADATA_CHANGED,
      changedFields,
      explanation: `Normalized version/metadata representation changed for ${curr.name} (${prevVer} → ${currVer}).`,
      warnings,
    };
  }

  // Case E: Non-comparable / invalid SemVer strings
  warnings.push({
    code: 'NON_COMPARABLE_VERSIONS',
    target: 'comparison',
    source: curr.identity,
    message: `Versions for ${curr.name} ("${prevVer}" vs "${currVer}") are not comparable SemVer 2.0.0 strings.`,
  });

  return {
    status: 'changed',
    changeType: ChangeType.VERSION_CHANGED,
    changedFields: ['version', ...metaChanges],
    explanation: `Version changed for ${curr.name} from "${prevVer}" to "${currVer}" (non-comparable SemVer).`,
    warnings,
  };
}

/**
 * Checks an inventory's component list for duplicate component identifiers (bomRef or PURL)
 * and emits diagnostic warnings without dropping duplicate entries.
 *
 * @param {Array<object>} items - Normalized components for one inventory.
 * @param {'previous' | 'current'} label - Inventory label.
 * @returns {Array<object>} Warning records.
 */
function checkDuplicates(items, label) {
  const warnings = [];
  const seenBomRefs = new Map();
  const seenPurls = new Map();

  for (const item of items) {
    if (item.bomRef) {
      const count = (seenBomRefs.get(item.bomRef) || 0) + 1;
      seenBomRefs.set(item.bomRef, count);
      if (count === 2) {
        warnings.push({
          code: 'DUPLICATE_COMPONENT_IDENTIFIER',
          target: label,
          source: item.source,
          message: `Duplicate bom-ref "${item.bomRef}" detected in ${label} SBOM for component ${item.name}.`,
        });
      }
    }

    if (item.purl) {
      const count = (seenPurls.get(item.purl) || 0) + 1;
      seenPurls.set(item.purl, count);
      if (count === 2 && item.purl !== item.bomRef) {
        warnings.push({
          code: 'DUPLICATE_COMPONENT_IDENTIFIER',
          target: label,
          source: item.source,
          message: `Duplicate PURL "${item.purl}" detected in ${label} SBOM for component ${item.name}.`,
        });
      }
    }
  }

  return warnings;
}

/**
 * Groups normalized components by their canonical package identity key.
 *
 * @param {Array<object>} items
 * @returns {Map<string, Array<object>>}
 */
function groupByIdentity(items) {
  const map = new Map();
  for (const item of items) {
    if (!map.has(item.identity)) {
      map.set(item.identity, []);
    }
    map.get(item.identity).push(item);
  }
  return map;
}

/**
 * Pairs components sharing the same canonical package identity across previous and current inventories.
 * Multi-pass matching preserves unchanged versions before pairing remaining upgraded/downgraded versions.
 *
 * @param {Array<object>} prevList
 * @param {Array<object>} currList
 * @returns {{
 *   pairs: Array<{ prev: object, curr: object }>,
 *   removed: Array<object>,
 *   added: Array<object>
 * }}
 */
function pairBucket(prevList, currList) {
  const usedPrev = new Set();
  const usedCurr = new Set();
  const pairs = [];

  const compareOrder = (a, b) => {
    const va = a.version || '';
    const vb = b.version || '';
    if (va !== vb) {
      const pa = va ? parseSemver(va) : null;
      const pb = vb ? parseSemver(vb) : null;
      if (pa && pb) {
        const cmp = compareSemver(va, vb);
        if (cmp !== 0) return cmp;
      }
      return va.localeCompare(vb);
    }
    return (a.bomRef || '').localeCompare(b.bomRef || '');
  };

  const sortedPrev = [...prevList].sort(compareOrder);
  const sortedCurr = [...currList].sort(compareOrder);

  // Pass 1: Exact version AND identical metadata match (preserves unchanged instances first)
  for (let i = 0; i < sortedPrev.length; i++) {
    if (usedPrev.has(i)) continue;
    for (let j = 0; j < sortedCurr.length; j++) {
      if (usedCurr.has(j)) continue;
      if (
        sortedPrev[i].version === sortedCurr[j].version &&
        detectChangedMetadataFields(sortedPrev[i], sortedCurr[j]).length === 0
      ) {
        usedPrev.add(i);
        usedCurr.add(j);
        pairs.push({ prev: sortedPrev[i], curr: sortedCurr[j] });
        break;
      }
    }
  }

  // Pass 2: Same version match (captures metadata-only changes even in multi-version buckets)
  for (let i = 0; i < sortedPrev.length; i++) {
    if (usedPrev.has(i)) continue;
    for (let j = 0; j < sortedCurr.length; j++) {
      if (usedCurr.has(j)) continue;
      if (sortedPrev[i].version === sortedCurr[j].version) {
        usedPrev.add(i);
        usedCurr.add(j);
        pairs.push({ prev: sortedPrev[i], curr: sortedCurr[j] });
        break;
      }
    }
  }

  // Pass 3: Matching bom-ref (when same component entry was upgraded while keeping its bom-ref)
  for (let i = 0; i < sortedPrev.length; i++) {
    if (usedPrev.has(i) || !sortedPrev[i].bomRef) continue;
    for (let j = 0; j < sortedCurr.length; j++) {
      if (usedCurr.has(j) || !sortedCurr[j].bomRef) continue;
      if (sortedPrev[i].bomRef === sortedCurr[j].bomRef) {
        usedPrev.add(i);
        usedCurr.add(j);
        pairs.push({ prev: sortedPrev[i], curr: sortedCurr[j] });
        break;
      }
    }
  }

  // Pass 4: Positional pairing of remaining items sharing the same package identity (e.g. version upgrade/downgrade)
  const remPrevIdx = [];
  const remCurrIdx = [];
  for (let i = 0; i < sortedPrev.length; i++) {
    if (!usedPrev.has(i)) remPrevIdx.push(i);
  }
  for (let j = 0; j < sortedCurr.length; j++) {
    if (!usedCurr.has(j)) remCurrIdx.push(j);
  }

  const pairCount = Math.min(remPrevIdx.length, remCurrIdx.length);
  for (let k = 0; k < pairCount; k++) {
    const pi = remPrevIdx[k];
    const ci = remCurrIdx[k];
    usedPrev.add(pi);
    usedCurr.add(ci);
    pairs.push({ prev: sortedPrev[pi], curr: sortedCurr[ci] });
  }

  const removed = sortedPrev.filter((_, i) => !usedPrev.has(i));
  const added = sortedCurr.filter((_, j) => !usedCurr.has(j));

  return { pairs, removed, added };
}

/**
 * Reconciles buckets where one side lacked a PURL/ecosystem ('unknown:<name>')
 * against an unambiguous sole known-ecosystem bucket ('<eco>:<name>') in the other inventory.
 * Emits an ambiguity warning rather than guessing when multiple ecosystems share the same package name.
 *
 * @param {Map<string, Array<object>>} prevGroups
 * @param {Map<string, Array<object>>} currGroups
 * @returns {{
 *   buckets: Array<{ identity: string, prevList: Array<object>, currList: Array<object> }>,
 *   warnings: Array<object>
 * }}
 */
function reconcileBuckets(prevGroups, currGroups) {
  const warnings = [];
  const buckets = [];
  const matchedIdentities = new Set();

  for (const identity of prevGroups.keys()) {
    if (currGroups.has(identity)) {
      matchedIdentities.add(identity);
      buckets.push({
        identity,
        prevList: prevGroups.get(identity),
        currList: currGroups.get(identity),
      });
    }
  }

  const remPrev = new Map();
  for (const [id, list] of prevGroups) {
    if (!matchedIdentities.has(id)) remPrev.set(id, list);
  }
  const remCurr = new Map();
  for (const [id, list] of currGroups) {
    if (!matchedIdentities.has(id)) remCurr.set(id, list);
  }

  const bridgeUnknownSide = (unknownMap, knownMap, isPrevUnknown) => {
    for (const [unkId, unkList] of Array.from(unknownMap.entries())) {
      if (!unkId.startsWith('unknown:')) continue;
      const pkgName = unkId.slice('unknown:'.length);
      const candidates = [];
      for (const [knownId, knownList] of knownMap.entries()) {
        if (!knownId.startsWith('unknown:') && knownList[0]?.name === pkgName) {
          candidates.push(knownId);
        }
      }

      if (candidates.length === 1) {
        const targetId = candidates[0];
        const knownList = knownMap.get(targetId);
        unknownMap.delete(unkId);
        knownMap.delete(targetId);
        buckets.push({
          identity: targetId,
          prevList: isPrevUnknown ? unkList : knownList,
          currList: isPrevUnknown ? knownList : unkList,
        });
      } else if (candidates.length > 1) {
        warnings.push({
          code: 'AMBIGUOUS_COMPONENT_MATCH',
          target: isPrevUnknown ? 'previous' : 'current',
          source: unkList[0]?.source || unkId,
          message: `Cannot unambiguously match "${pkgName}" with unknown ecosystem against multiple ecosystems (${candidates.join(', ')}).`,
        });
      }
    }
  };

  bridgeUnknownSide(remPrev, remCurr, true);
  bridgeUnknownSide(remCurr, remPrev, false);

  for (const [id, list] of remPrev) {
    buckets.push({ identity: id, prevList: list, currList: [] });
  }
  for (const [id, list] of remCurr) {
    buckets.push({ identity: id, prevList: [], currList: list });
  }

  buckets.sort((a, b) => a.identity.localeCompare(b.identity));

  return { buckets, warnings };
}

/**
 * Compares two SBOM inventories (previousBom vs currentBom) and identifies
 * added, removed, changed (upgraded, downgraded, metadata-changed, version-changed),
 * and unchanged dependencies.
 *
 * Does not mutate inputs or perform network calls.
 *
 * @param {object} previousBom - The older SBOM inventory object.
 * @param {object} currentBom - The newer SBOM inventory object.
 * @param {object} [options={}] - Optional configuration flags.
 * @param {boolean} [options.includeRoot=false] - Whether to include root components from scanResult objects.
 * @returns {{
 *   status: 'completed' | 'failed',
 *   summary: { added: number, removed: number, changed: number, unchanged: number },
 *   added: Array<object>,
 *   removed: Array<object>,
 *   changed: Array<object>,
 *   unchanged: Array<object>,
 *   errors: Array<object>,
 *   warnings: Array<object>
 * }} Structured comparison result.
 */
export function compareInventories(previousBom, currentBom, options = {}) {
  const errors = [];
  const warnings = [];

  const prevExtracted = extractInventory(previousBom, 'previous', options);
  const currExtracted = extractInventory(currentBom, 'current', options);

  if (!prevExtracted.valid && prevExtracted.error) {
    errors.push(prevExtracted.error);
  }
  if (!currExtracted.valid && currExtracted.error) {
    errors.push(currExtracted.error);
  }

  if (errors.length > 0) {
    return {
      status: ComparisonStatus.FAILED,
      summary: { added: 0, removed: 0, changed: 0, unchanged: 0 },
      added: [],
      removed: [],
      changed: [],
      unchanged: [],
      errors,
      warnings,
    };
  }

  // Normalize all components and collect non-fatal warnings
  const prevNormalized = [];
  for (let i = 0; i < prevExtracted.components.length; i++) {
    const norm = normalizeComponent(prevExtracted.components[i], i, 'previous');
    warnings.push(...norm.warnings);
    if (norm.valid) {
      prevNormalized.push(norm);
    }
  }

  const currNormalized = [];
  for (let i = 0; i < currExtracted.components.length; i++) {
    const norm = normalizeComponent(currExtracted.components[i], i, 'current');
    warnings.push(...norm.warnings);
    if (norm.valid) {
      currNormalized.push(norm);
    }
  }

  warnings.push(...checkDuplicates(prevNormalized, 'previous'));
  warnings.push(...checkDuplicates(currNormalized, 'current'));

  const prevGroups = groupByIdentity(prevNormalized);
  const currGroups = groupByIdentity(currNormalized);

  const { buckets, warnings: reconcileWarnings } = reconcileBuckets(prevGroups, currGroups);
  warnings.push(...reconcileWarnings);

  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];

  for (const { prevList, currList } of buckets) {
    const { pairs, removed: remList, added: addList } = pairBucket(prevList, currList);

    for (const item of addList) {
      added.push({
        identity: item.identity,
        name: item.name,
        ecosystem: item.ecosystem,
        version: item.version,
        purl: item.purl,
        bomRef: item.bomRef,
        changeType: ChangeType.ADDED,
        component: item.snapshot,
        explanation: `Added ${item.name}${item.version ? `@${item.version}` : ''}.`,
      });
    }

    for (const item of remList) {
      removed.push({
        identity: item.identity,
        name: item.name,
        ecosystem: item.ecosystem,
        version: item.version,
        purl: item.purl,
        bomRef: item.bomRef,
        changeType: ChangeType.REMOVED,
        component: item.snapshot,
        explanation: `Removed ${item.name}${item.version ? `@${item.version}` : ''}.`,
      });
    }

    for (const { prev, curr } of pairs) {
      const classification = classifyComponentPair(prev, curr);
      warnings.push(...classification.warnings);

      if (classification.status === 'unchanged') {
        unchanged.push({
          identity: curr.identity,
          name: curr.name,
          ecosystem: curr.ecosystem,
          version: curr.version,
          purl: curr.purl,
          bomRef: curr.bomRef,
          component: curr.snapshot,
          explanation: classification.explanation,
        });
      } else {
        changed.push({
          identity: curr.identity,
          name: curr.name,
          ecosystem: curr.ecosystem,
          changeType: classification.changeType,
          previousVersion: prev.version,
          currentVersion: curr.version,
          previousComponent: prev.snapshot,
          currentComponent: curr.snapshot,
          changedFields: classification.changedFields,
          explanation: classification.explanation,
        });
      }
    }
  }

  return {
    status: ComparisonStatus.COMPLETED,
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      unchanged: unchanged.length,
    },
    added,
    removed,
    changed,
    unchanged,
    errors,
    warnings,
  };
}

export default compareInventories;

