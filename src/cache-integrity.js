// Cached-resource integrity checker.
//
// The client holds a sparse local cache of a resource (at most 1 MiB) and
// wants to know which fixed-size blocks are still good after, say, a crash or
// a suspect disk. It submits:
//
//   - the resource `size` and the `blockBytes` block size;
//   - the ordered per-block SHA-256 digests (lowercase hex), exactly
//     ceil(size/blockBytes) of them;
//   - sparse cached fragments ({start, dataBase64}), shaped exactly like the
//     /assemble-response fragments: strictly canonical base64, each one fully
//     inside the resource, at most 1 MiB of decoded bytes in total.
//
// The fragments are merged into one byte image. Overlapping fragments that
// carry the same bytes coexist; any position where overlapping fragments
// disagree marks the block containing that position as `corrupt` (the true
// byte is unknowable, so a digest could never rehabilitate it). Each block
// then falls into exactly one state:
//
//   - `missing`  — not fully covered by the merged fragments (and not
//                  conflicted);
//   - `corrupt`  — carries a fragment conflict, or is fully covered but its
//                  merged bytes hash to something other than the submitted
//                  digest;
//   - `verified` — fully covered and digest-identical.
//
// `refetchRanges` merges the byte spans of every missing/corrupt block into
// the fewest closed intervals the client can re-fetch. An empty resource has
// no blocks and returns empty results.

import { createHash } from 'node:crypto';

export const MAX_FRAGMENTS = 1024;
export const MAX_RESOURCE_BYTES = 1024 * 1024; // 1 MiB resource
export const MAX_FRAGMENT_BYTES = 1024 * 1024; // 1 MiB total decoded input
// blockBytes is at least 1, so the digest count can never exceed the byte count.
export const MAX_BLOCK_COUNT = MAX_RESOURCE_BYTES;
// Headroom above the 1 MiB decoded-input rule, mirroring /assemble-response;
// the semantic FRAGMENTS_TOO_LARGE check enforces the real limit.
export const MAX_FRAGMENT_BASE64_LENGTH = 1_400_000;

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * Check the integrity of a cached resource against per-block SHA-256 digests.
 *
 * @returns a result object with `statusCode` 200 carrying the verified /
 *          missing / corrupt block indices and the merged refetch ranges, or
 *          a 400 result describing the first validation failure.
 */
export function checkCacheIntegrity(options) {
  const { size, blockBytes, blockHashes, fragments } = options;

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
  if (!Array.isArray(blockHashes)) {
    return fail('INVALID_BLOCK_HASHES', 'blockHashes must be an array of SHA-256 hex digests');
  }

  const blockCount = size === 0 ? 0 : Math.floor((size - 1) / blockBytes) + 1;
  if (blockHashes.length !== blockCount) {
    return fail(
      'HASH_COUNT_MISMATCH',
      `blockHashes carries ${blockHashes.length} digest${blockHashes.length === 1 ? '' : 's'}; ` +
        `it must carry ${blockCount} (= ceil(${size}/${blockBytes}))`,
    );
  }
  for (let i = 0; i < blockHashes.length; i += 1) {
    if (typeof blockHashes[i] !== 'string' || !SHA256_HEX_RE.test(blockHashes[i])) {
      return fail(
        'INVALID_BLOCK_HASH',
        `blockHashes[${i}] must be a 64-character lowercase hexadecimal SHA-256 digest`,
      );
    }
  }

  const decoded = decodeFragments(fragments, size);
  if (decoded.error) return decoded.error;

  if (size === 0) {
    return {
      statusCode: 200,
      resource: { size, blockBytes },
      blockCount: 0,
      verified: [],
      missing: [],
      corrupt: [],
      refetchRanges: [],
    };
  }

  // Merge every fragment into one byte image, remembering which positions at
  // least one fragment covers and which blocks hold disagreeing overlaps.
  const data = Buffer.alloc(size);
  const covered = new Uint8Array(size);
  const conflictBlocks = new Set();
  for (const fragment of decoded.fragments) {
    for (let j = 0; j < fragment.data.length; j += 1) {
      const position = fragment.start + j;
      const byte = fragment.data[j];
      if (covered[position] === 0) {
        data[position] = byte;
        covered[position] = 1;
      } else if (data[position] !== byte) {
        // The true byte is ambiguous; this block can never verify.
        conflictBlocks.add(Math.floor(position / blockBytes));
      }
    }
  }

  const verified = [];
  const missing = [];
  const corrupt = [];
  for (let i = 0; i < blockCount; i += 1) {
    const blockStart = i * blockBytes;
    const blockEnd = Math.min(blockStart + blockBytes, size);

    let complete = true;
    for (let position = blockStart; position < blockEnd; position += 1) {
      if (covered[position] === 0) {
        complete = false;
        break;
      }
    }

    // A conflict outranks incomplete coverage: the block must be refetched
    // either way and its partially missing bytes are already in refetchRanges.
    if (conflictBlocks.has(i)) {
      corrupt.push(i);
      continue;
    }
    if (!complete) {
      missing.push(i);
      continue;
    }
    const digest = createHash('sha256').update(data.subarray(blockStart, blockEnd)).digest('hex');
    if (digest === blockHashes[i]) {
      verified.push(i);
    } else {
      corrupt.push(i);
    }
  }

  // Union of missing and corrupt block spans, merged across adjacent blocks.
  const badBlocks = missing.concat(corrupt).sort((a, b) => a - b);
  const refetchRanges = [];
  for (const i of badBlocks) {
    const start = i * blockBytes;
    const end = Math.min(start + blockBytes, size) - 1;
    const last = refetchRanges[refetchRanges.length - 1];
    if (last && start <= last.end + 1) {
      if (end > last.end) last.end = end;
    } else {
      refetchRanges.push({ start, end });
    }
  }

  return {
    statusCode: 200,
    resource: { size, blockBytes },
    blockCount,
    verified,
    missing,
    corrupt,
    refetchRanges,
  };
}

/**
 * Validate the fragment list and decode every dataBase64 payload. Mirrors the
 * /assemble-response rules: each fragment must lie fully inside the resource
 * and carry at least one byte; together they may not exceed the 1 MiB
 * decoded-input budget.
 */
function decodeFragments(fragments, size) {
  if (!Array.isArray(fragments)) {
    return {
      error: fail('INVALID_FRAGMENTS', 'fragments must be an array of {start, dataBase64} objects'),
    };
  }
  if (fragments.length > MAX_FRAGMENTS) {
    return {
      error: fail(
        'TOO_MANY_FRAGMENTS',
        `fragments carries ${fragments.length} items; at most ${MAX_FRAGMENTS} are allowed`,
      ),
    };
  }

  const decoded = [];
  let totalBytes = 0;
  for (let i = 0; i < fragments.length; i += 1) {
    const fragment = fragments[i];
    if (fragment === null || typeof fragment !== 'object' || Array.isArray(fragment)) {
      return {
        error: fail('INVALID_FRAGMENT', `fragments[${i}] must be an object with start and dataBase64`),
      };
    }
    const { start, dataBase64 } = fragment;
    if (!Number.isSafeInteger(start) || start < 0) {
      return {
        error: fail('INVALID_FRAGMENT', `fragments[${i}].start must be a non-negative safe integer`),
      };
    }
    const data = decodeBase64(dataBase64);
    if (data === null) {
      return {
        error: fail(
          'INVALID_FRAGMENT_BASE64',
          `fragments[${i}].dataBase64 must be a non-empty, canonically padded standard base64 string`,
        ),
      };
    }
    // Compared without ever summing past Number.MAX_SAFE_INTEGER.
    if (start >= size || data.length > size - start) {
      return {
        error: fail(
          'FRAGMENT_OUT_OF_BOUNDS',
          `fragments[${i}] covers ${data.length} byte(s) from offset ${start}, ` +
            `which lies outside the ${size}-byte resource`,
        ),
      };
    }
    totalBytes += data.length;
    if (totalBytes > MAX_FRAGMENT_BYTES) {
      return {
        error: fail(
          'FRAGMENTS_TOO_LARGE',
          `fragments decode to more than ${MAX_FRAGMENT_BYTES} bytes (1 MiB) in total`,
        ),
      };
    }
    decoded.push({ start, data });
  }
  return { fragments: decoded };
}

/**
 * Decode strictly canonical standard-alphabet base64. Returns null for empty
 * input, illegal characters, missing/extra padding or any non-canonical
 * quantum (round-tripping through Node's lenient decoder detects the rest).
 */
function decodeBase64(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) return null;
  if (!BASE64_RE.test(value)) return null;
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length === 0 || buffer.toString('base64') !== value) return null;
  return buffer;
}

function fail(code, message) {
  return {
    statusCode: 400,
    code,
    error: 'Bad Request',
    message,
  };
}
