// Cache retention planner.
//
// Given a resource size, the byte intervals already held in cache (closed
// intervals, possibly unordered, overlapping or adjacent), the expected
// access intervals — each a closed interval carrying a positive integer
// weight — and a byte budget, decide which cached bytes to keep:
//
//   - overlapping cache intervals are counted once (merged first);
//   - overlapping accesses accumulate: a byte's value is the sum of the
//     weights of every access interval covering it;
//   - only cached bytes with a positive accumulated weight are worth
//     keeping;
//   - the budget is filled by descending per-byte weight, ties broken by
//     ascending offset, truncating inside an interval (keeping its
//     lowest-offset bytes) when the budget runs out mid-segment;
//   - the selected bytes are merged back into disjoint ascending closed
//     intervals (adjacent selections merge into one).

export const MAX_CACHED_INTERVALS = 1000;
export const MAX_ACCESS_INTERVALS = 1000;
export const MAX_ACCESS_WEIGHT = 1_000_000;

/**
 * Plan which cached bytes to retain under a byte budget.
 *
 * @returns a result object with `statusCode` 200 carrying `retained`
 *          (merged closed intervals, ascending by offset), `retainedBytes`
 *          and `unusedBytes` (budget left over when the positive-value
 *          cached bytes could not fill it), or a 400 result describing the
 *          first validation failure.
 */
export function planCacheRetention(options) {
  const { size, cached, accesses, budgetBytes } = options;

  if (!Number.isSafeInteger(size) || size < 0) {
    return fail('INVALID_SIZE', 'size must be a non-negative safe integer');
  }
  if (!Number.isSafeInteger(budgetBytes) || budgetBytes < 0) {
    return fail('INVALID_BUDGET', 'budgetBytes must be a non-negative safe integer');
  }

  const cachedError = validateCached(cached, size);
  if (cachedError) return cachedError;
  const accessesError = validateAccesses(accesses, size);
  if (accessesError) return accessesError;

  const candidates = collectCandidates(cached, accesses);

  // Highest per-byte weight first; equal weights take the lower offset first.
  candidates.sort((a, b) => b.weight - a.weight || a.start - b.start);

  const selected = [];
  let remaining = budgetBytes;
  for (const candidate of candidates) {
    if (remaining === 0) break;
    const length = candidate.end - candidate.start + 1;
    if (length <= remaining) {
      selected.push({ start: candidate.start, end: candidate.end });
      remaining -= length;
    } else {
      // Truncation inside an interval keeps its lowest-offset bytes.
      selected.push({ start: candidate.start, end: candidate.start + remaining - 1 });
      remaining = 0;
    }
  }

  const retained = mergeIntervals(selected);
  const retainedBytes = retained.reduce(
    (sum, interval) => sum + (interval.end - interval.start + 1),
    0,
  );

  return {
    statusCode: 200,
    retained,
    retainedBytes,
    unusedBytes: budgetBytes - retainedBytes,
  };
}

function validateCached(cached, size) {
  if (!Array.isArray(cached)) {
    return fail('INVALID_CACHED', 'cached must be an array of {start, end} intervals');
  }
  if (cached.length > MAX_CACHED_INTERVALS) {
    return fail(
      'TOO_MANY_CACHED_INTERVALS',
      `cached carries ${cached.length} intervals; at most ${MAX_CACHED_INTERVALS} are allowed`,
    );
  }
  for (let i = 0; i < cached.length; i += 1) {
    const interval = cached[i];
    if (interval === null || typeof interval !== 'object' || Array.isArray(interval)) {
      return fail('INVALID_CACHED_RANGE', `cached[${i}] must be an object with start and end`);
    }
    const { start, end } = interval;
    if (!Number.isSafeInteger(start) || start < 0) {
      return fail('INVALID_CACHED_RANGE', `cached[${i}].start must be a non-negative safe integer`);
    }
    if (!Number.isSafeInteger(end) || end < 0) {
      return fail('INVALID_CACHED_RANGE', `cached[${i}].end must be a non-negative safe integer`);
    }
    if (start > end) {
      return fail('INVALID_CACHED_RANGE', `cached[${i}] has start ${start} after end ${end}`);
    }
    if (end >= size) {
      return fail(
        'CACHED_RANGE_OUT_OF_BOUNDS',
        `cached[${i}] end ${end} lies outside the ${size}-byte resource`,
      );
    }
  }
  return null;
}

function validateAccesses(accesses, size) {
  if (!Array.isArray(accesses)) {
    return fail(
      'INVALID_ACCESSES',
      'accesses must be an array of {start, end, weight} intervals',
    );
  }
  if (accesses.length > MAX_ACCESS_INTERVALS) {
    return fail(
      'TOO_MANY_ACCESS_INTERVALS',
      `accesses carries ${accesses.length} intervals; at most ${MAX_ACCESS_INTERVALS} are allowed`,
    );
  }
  for (let i = 0; i < accesses.length; i += 1) {
    const interval = accesses[i];
    if (interval === null || typeof interval !== 'object' || Array.isArray(interval)) {
      return fail(
        'INVALID_ACCESS_RANGE',
        `accesses[${i}] must be an object with start, end and weight`,
      );
    }
    const { start, end, weight } = interval;
    if (!Number.isSafeInteger(start) || start < 0) {
      return fail('INVALID_ACCESS_RANGE', `accesses[${i}].start must be a non-negative safe integer`);
    }
    if (!Number.isSafeInteger(end) || end < 0) {
      return fail('INVALID_ACCESS_RANGE', `accesses[${i}].end must be a non-negative safe integer`);
    }
    if (start > end) {
      return fail('INVALID_ACCESS_RANGE', `accesses[${i}] has start ${start} after end ${end}`);
    }
    if (end >= size) {
      return fail(
        'ACCESS_RANGE_OUT_OF_BOUNDS',
        `accesses[${i}] end ${end} lies outside the ${size}-byte resource`,
      );
    }
    if (!Number.isSafeInteger(weight) || weight < 1) {
      return fail('INVALID_ACCESS_WEIGHT', `accesses[${i}].weight must be a positive safe integer`);
    }
    if (weight > MAX_ACCESS_WEIGHT) {
      return fail(
        'ACCESS_WEIGHT_TOO_LARGE',
        `accesses[${i}].weight is ${weight}; at most ${MAX_ACCESS_WEIGHT} is allowed`,
      );
    }
  }
  return null;
}

/**
 * Intersect the merged cache with the accumulated access weights and return
 * the candidate segments: maximal constant-weight spans of cached bytes with
 * positive weight, ascending by offset. A sweep-line over the access
 * endpoints keeps the accumulated weight constant between two consecutive
 * event positions; each such span is then cut against the merged cache.
 */
function collectCandidates(cached, accesses) {
  const cache = mergeIntervals(cached);
  if (cache.length === 0 || accesses.length === 0) return [];

  const events = [];
  for (const access of accesses) {
    events.push({ pos: access.start, delta: access.weight });
    // end <= size - 1 <= Number.MAX_SAFE_INTEGER - 1, so end + 1 stays safe.
    events.push({ pos: access.end + 1, delta: -access.weight });
  }
  events.sort((a, b) => a.pos - b.pos);

  const candidates = [];
  let weight = 0;
  let spanStart = 0;
  let cacheIndex = 0;
  for (const event of events) {
    if (event.pos > spanStart) {
      if (weight > 0) {
        const spanEnd = event.pos - 1;
        while (cacheIndex < cache.length && cache[cacheIndex].end < spanStart) cacheIndex += 1;
        // Both lists ascend, so every cache interval touched here overlaps
        // the span; the intersections are non-empty by construction.
        for (let j = cacheIndex; j < cache.length && cache[j].start <= spanEnd; j += 1) {
          candidates.push({
            start: Math.max(cache[j].start, spanStart),
            end: Math.min(cache[j].end, spanEnd),
            weight,
          });
        }
      }
      spanStart = event.pos;
    }
    weight += event.delta;
  }
  return candidates;
}

/**
 * Sort closed intervals by start offset and merge overlapping or adjacent
 * ones ([0-9] and [10-19] merge into [0-19]).
 */
function mergeIntervals(intervals) {
  const sorted = intervals
    .map((interval) => ({ start: interval.start, end: interval.end }))
    .sort((a, b) => a.start - b.start || a.end - b.end);

  const merged = [];
  for (const interval of sorted) {
    const last = merged[merged.length - 1];
    if (last && interval.start <= last.end + 1) {
      if (interval.end > last.end) last.end = interval.end;
    } else {
      merged.push({ start: interval.start, end: interval.end });
    }
  }
  return merged;
}

function fail(code, message) {
  return {
    statusCode: 400,
    code,
    error: 'Bad Request',
    message,
  };
}
