// Sparse-cache integrity checker.
//
// The client holds sparse fragments of a resource (the same
// {start, dataBase64} shape POST /assemble-response consumes) together with
// the resource's block manifest: the resource size, a block size and one
// SHA-256 hexadecimal digest per block in order. It asks: "which of my
// blocks are trustworthy?"
//
// The fragments are validated exactly as for /assemble-response (in-bounds,
// canonically padded standard base64, at most 1 MiB decoded in total) and
// merged into one canonical sparse cache: overlapping bytes must agree,
// otherwise every block touched by a disagreeing position is corrupt.
//
// Every block is then classified independently:
//   - corrupt: a fragment conflict touches the block, or the cache fully
//     covers it but its SHA-256 differs from the submitted digest;
//   - missing: no conflict touches it but the cache does not cover every
//     one of its bytes (a hash cannot even be computed);
//   - verified: fully covered, conflict-free and digest-matching.
//
// refetchRanges is the byte-level union (merged closed intervals) of every
// missing or corrupt block: the ranges a client must re-download.

import { createHash } from 'node:crypto';
import {
  decodeFragments,
  buildCache,
  readRange,
} from './assemble.js';

export const MAX_RESOURCE_BYTES = 1024 * 1024; // size must not exceed 1 MiB
export const MAX_BLOCK_DIGEST_LENGTH = 64; // SHA-256 hexadecimal

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * Verify sparse cached fragments against a per-block SHA-256 manifest.
 *
 * @returns a result object with `statusCode` 200 carrying `blocksCount`,
 *          the `verified` / `missing` / `corrupt` block-index lists and
 *          `refetchRanges` (merged closed byte intervals spanning every
 *          missing or corrupt block), or a 400 result describing the first
 *          validation failure.
 */
export function checkCacheIntegrity(options) {
  const { size, blockBytes, digests, fragments } = options;

  if (!Number.isSafeInteger(size) || size < 0) {
    return fail('INVALID_SIZE', 'size must be a non-negative safe integer');
  }
  if (size > MAX_RESOURCE_BYTES) {
    return fail(
      'RESOURCE_TOO_LARGE',
      `size is ${size}; resources of at most ${MAX_RESOURCE_BYTES} bytes (1 MiB) are supported`,
    );
  }
  if (!Number.isSafeInteger(blockBytes) || blockBytes < 1) {
    return fail('INVALID_BLOCK_BYTES', 'blockBytes must be a positive safe integer');
  }

  const blocksCount = Math.ceil(size / blockBytes);
  if (!Array.isArray(digests)) {
    return fail('INVALID_DIGESTS', 'digests must be an array of lowercase SHA-256 hexadecimal strings');
  }
  if (digests.length !== blocksCount) {
    return fail(
      'INVALID_DIGEST_COUNT',
      `digests carries ${digests.length} entr${digests.length === 1 ? 'y' : 'ies'} but size=${size} and ` +
        `blockBytes=${blockBytes} demand ${blocksCount} (ceil(size/blockBytes))`,
    );
  }
  for (let i = 0; i < digests.length; i += 1) {
    if (typeof digests[i] !== 'string' || !SHA256_HEX_RE.test(digests[i])) {
      return fail(
        'INVALID_DIGEST',
        `digests[${i}] must be a 64-character lowercase hexadecimal SHA-256 digest`,
      );
    }
  }

  // Same strict decoding, bounds and 1 MiB total-input rule as
  // /assemble-response, yielding {start, end, data} intervals.
  const decoded = decodeFragments(fragments, size);
  if (decoded.error) return decoded.error;

  // An empty resource has no blocks and therefore nothing to classify.
  if (size === 0) {
    return {
      statusCode: 200,
      blocksCount: 0,
      verified: [],
      missing: [],
      corrupt: [],
      refetchRanges: [],
    };
  }

  const cache = buildCache(decoded.fragments);

  const verified = [];
  const missing = [];
  const corrupt = [];

  for (let index = 0; index < blocksCount; index += 1) {
    const start = index * blockBytes;
    const end = Math.min(start + blockBytes, size) - 1;

    // A fragment disagreement poisons every block it touches, independently
    // of whether the block is otherwise fully covered.
    if (intervalListTouchesBlock(cache.conflicts, start, end)) {
      corrupt.push(index);
      continue;
    }
    if (!blockIsCovered(cache.intervals, start, end)) {
      missing.push(index);
      continue;
    }

    const digest = createHash('sha256').update(readRange(cache.intervals, start, end)).digest('hex');
    if (digest === digests[index]) {
      verified.push(index);
    } else {
      corrupt.push(index);
    }
  }

  return {
    statusCode: 200,
    blocksCount,
    verified,
    missing,
    corrupt,
    refetchRanges: blocksToRanges(missing.concat(corrupt).sort((a, b) => a - b), blockBytes, size),
  };
}

/**
 * Whether any closed interval in a sorted, disjoint list overlaps the block
 * span [start, end]. The lists are short, so a plain scan is sufficient;
 * block spans are disjoint and ascend, so an interval ending before the
 * block can never matter again.
 */
function intervalListTouchesBlock(intervals, start, end) {
  for (const interval of intervals) {
    if (interval.end < start) continue;
    if (interval.start > end) break;
    return true;
  }
  return false;
}

/**
 * Whether the merged cache intervals cover every byte of [start, end].
 * Walks the disjoint ascending intervals and verifies their covered length
 * fills the whole span.
 */
function blockIsCovered(intervals, start, end) {
  let cursor = start;
  for (const interval of intervals) {
    if (interval.end < cursor) continue;
    if (interval.start > cursor) return false;
    cursor = interval.end + 1;
    if (cursor > end) return true;
  }
  return cursor > end;
}

/**
 * Expand block indices to their byte spans and merge overlapping or adjacent
 * spans into closed intervals. Sorted indices already ascend, and adjacent
 * blocks share a boundary (block k ends where block k+1 starts).
 */
function blocksToRanges(indices, blockBytes, size) {
  const ranges = [];
  for (const index of indices) {
    const start = index * blockBytes;
    const end = Math.min(start + blockBytes, size) - 1;
    const last = ranges[ranges.length - 1];
    if (last && start <= last.end + 1) {
      if (end > last.end) last.end = end;
    } else {
      ranges.push({ start, end });
    }
  }
  return ranges;
}

function fail(code, message) {
  return {
    statusCode: 400,
    code,
    error: 'Bad Request',
    message,
  };
}
