import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildApp } from '../src/app.js';

const app = buildApp();
const url = '/cache-integrity-check';

function check(payload) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

// Deterministic position-dependent content: the byte at absolute offset o is
// o % 251, so the true digest of any block is computable.
function content(start, length) {
  const buffer = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) buffer[i] = (start + i) % 251;
  return buffer;
}

const frag = (start, data) => ({
  start,
  dataBase64: (Buffer.isBuffer(data) ? data : content(start, data)).toString('base64'),
});
const digest = (buffer) => createHash('sha256').update(buffer).digest('hex');

// Build the ordered digest list for the true content over [0, size).
function trueHashes(size, blockBytes) {
  const count = size === 0 ? 0 : Math.floor((size - 1) / blockBytes) + 1;
  const hashes = [];
  for (let i = 0; i < count; i += 1) {
    const start = i * blockBytes;
    const end = Math.min(start + blockBytes, size);
    hashes.push(digest(content(start, end - start)));
  }
  return hashes;
}

test('fully covered blocks with correct hashes are all verified', async () => {
  const res = await check({
    size: 100,
    blockBytes: 25,
    blockHashes: trueHashes(100, 25),
    fragments: [frag(0, 100)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), {
    statusCode: 200,
    resource: { size: 100, blockBytes: 25 },
    blockCount: 4,
    verified: [0, 1, 2, 3],
    missing: [],
    corrupt: [],
    refetchRanges: [],
  });
});

test('an empty resource returns empty results', async () => {
  const res = await check({ size: 0, blockBytes: 1024, blockHashes: [], fragments: [] });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), {
    statusCode: 200,
    resource: { size: 0, blockBytes: 1024 },
    blockCount: 0,
    verified: [],
    missing: [],
    corrupt: [],
    refetchRanges: [],
  });
});

test('blocks may be covered by several adjacent fragments', async () => {
  const res = await check({
    size: 50,
    blockBytes: 10,
    blockHashes: trueHashes(50, 10),
    fragments: [frag(0, 10), frag(10, 25), frag(35, 15)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().verified, [0, 1, 2, 3, 4]);
  assert.deepEqual(res.json().refetchRanges, []);
});

test('overlapping fragments carrying identical bytes coexist', async () => {
  const res = await check({
    size: 30,
    blockBytes: 15,
    blockHashes: trueHashes(30, 15),
    fragments: [frag(0, 20), frag(15, 15)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().verified, [0, 1]);
});

test('uncovered blocks are missing and the final short block is handled', async () => {
  // 50 bytes / block 16 -> blocks: [0,15] [16,31] [32,47] [48,49].
  const res = await check({
    size: 50,
    blockBytes: 16,
    blockHashes: trueHashes(50, 16),
    fragments: [frag(16, 16)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.blockCount, 4);
  assert.deepEqual(body.verified, [1]);
  assert.deepEqual(body.missing, [0, 2, 3]);
  assert.deepEqual(body.corrupt, []);
  // Missing blocks 2 and 3 are adjacent byte spans and merge into one range.
  assert.deepEqual(body.refetchRanges, [
    { start: 0, end: 15 },
    { start: 32, end: 49 },
  ]);
});

test('a partially covered block is missing', async () => {
  const res = await check({
    size: 20,
    blockBytes: 10,
    blockHashes: trueHashes(20, 10),
    fragments: [frag(0, 5)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, []);
  assert.deepEqual(body.missing, [0, 1]);
  assert.deepEqual(body.refetchRanges, [{ start: 0, end: 19 }]);
});

test('fully covered bytes with a mismatched digest are corrupt', async () => {
  const hashes = trueHashes(40, 10);
  hashes[1] = '0'.repeat(64);
  const res = await check({
    size: 40,
    blockBytes: 10,
    blockHashes: hashes,
    fragments: [frag(0, 40)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 2, 3]);
  assert.deepEqual(body.corrupt, [1]);
  assert.deepEqual(body.missing, []);
  assert.deepEqual(body.refetchRanges, [{ start: 10, end: 19 }]);
});

test('overlapping fragments that disagree on bytes mark the involved block corrupt', async () => {
  const evil = content(0, 10);
  evil[5] = (evil[5] + 1) % 256; // disagrees at absolute offset 5 -> block 0
  const res = await check({
    size: 40,
    blockBytes: 10,
    blockHashes: trueHashes(40, 10),
    fragments: [frag(0, 40), frag(0, evil)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.corrupt, [0]);
  assert.deepEqual(body.verified, [1, 2, 3]);
  assert.deepEqual(body.refetchRanges, [{ start: 0, end: 9 }]);
});

test('a conflict makes a block corrupt even when it is also incomplete', async () => {
  // First fragment supplies bytes 5-9; the conflicting overlap is at 5-9,
  // bytes 0-4 are never covered. Block 0 is both incomplete and conflicted.
  const partA = content(5, 5);
  const partB = content(5, 5);
  partB[0] = (partB[0] + 1) % 256;
  const res = await check({
    size: 20,
    blockBytes: 10,
    blockHashes: trueHashes(20, 10),
    fragments: [frag(5, partA), frag(5, partB)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.corrupt, [0]);
  assert.deepEqual(body.missing, [1]);
  // Block 0's full span is in the refetch range regardless of the hole in it.
  assert.deepEqual(body.refetchRanges, [{ start: 0, end: 19 }]);
});

test('missing and corrupt block spans are merged into closed refetch ranges', async () => {
  const hashes = trueHashes(80, 10);
  hashes[2] = 'a'.repeat(64); // covered but hash mismatch -> corrupt
  hashes[6] = 'b'.repeat(64); // never covered -> missing (hash never checked)
  const res = await check({
    size: 80,
    blockBytes: 10,
    blockHashes: hashes,
    fragments: [frag(0, 40)], // covers blocks 0-3
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 1, 3]);
  assert.deepEqual(body.corrupt, [2]);
  assert.deepEqual(body.missing, [4, 5, 6, 7]);
  // bad blocks sorted: 2,4,5,6,7 -> [20,29] and [40,79].
  assert.deepEqual(body.refetchRanges, [
    { start: 20, end: 29 },
    { start: 40, end: 79 },
  ]);
});

test('blockBytes larger than size yields one short final block', async () => {
  const res = await check({
    size: 5,
    blockBytes: 1024,
    blockHashes: trueHashes(5, 1024),
    fragments: [frag(0, 5)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.blockCount, 1);
  assert.deepEqual(body.verified, [0]);
});

test('one-byte blocks are supported', async () => {
  const res = await check({
    size: 3,
    blockBytes: 1,
    blockHashes: trueHashes(3, 1),
    fragments: [frag(0, content(0, 2)), frag(2, 1)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().verified, [0, 1, 2]);
});

test('the digest count must equal ceil(size/blockBytes)', async () => {
  const tooFew = await check({ size: 40, blockBytes: 10, blockHashes: trueHashes(40, 10).slice(1), fragments: [] });
  assert.equal(tooFew.statusCode, 400);
  assert.equal(tooFew.json().code, 'HASH_COUNT_MISMATCH');

  const tooMany = await check({
    size: 40,
    blockBytes: 10,
    blockHashes: [...trueHashes(40, 10), 'f'.repeat(64)],
    fragments: [],
  });
  assert.equal(tooMany.statusCode, 400);
  assert.equal(tooMany.json().code, 'HASH_COUNT_MISMATCH');

  const emptyMismatch = await check({
    size: 0,
    blockBytes: 10,
    blockHashes: ['f'.repeat(64)],
    fragments: [],
  });
  assert.equal(emptyMismatch.statusCode, 400);
  assert.equal(emptyMismatch.json().code, 'HASH_COUNT_MISMATCH');
});

test('digests must be 64-character lowercase hex strings', async () => {
  for (const bad of ['00', 'g'.repeat(64), 'A'.repeat(64), '0'.repeat(63)]) {
    const res = await check({ size: 10, blockBytes: 10, blockHashes: [bad], fragments: [] });
    assert.equal(res.statusCode, 400, `expected 400 for digest=${JSON.stringify(bad)}`);
  }
});

test('a fragment extending past the resource end is rejected', async () => {
  const res = await check({
    size: 10,
    blockBytes: 5,
    blockHashes: trueHashes(10, 5),
    fragments: [frag(8, 5)],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENT_OUT_OF_BOUNDS');
});

test('a fragment starting at the resource end is rejected', async () => {
  const res = await check({
    size: 10,
    blockBytes: 5,
    blockHashes: trueHashes(10, 5),
    fragments: [frag(10, 1)],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENT_OUT_OF_BOUNDS');
});

test('fragments are rejected on an empty resource', async () => {
  const res = await check({ size: 0, blockBytes: 10, blockHashes: [], fragments: [frag(0, 1)] });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENT_OUT_OF_BOUNDS');
});

test('malformed base64 is rejected', async () => {
  for (const dataBase64 of ['####', 'QR==', 'QQ==QQ==', 'Q Q==']) {
    const res = await check({
      size: 100,
      blockBytes: 100,
      blockHashes: trueHashes(100, 100),
      fragments: [{ start: 0, dataBase64 }],
    });
    assert.equal(res.statusCode, 400, `expected 400 for dataBase64=${dataBase64}`);
    assert.equal(res.json().code, 'INVALID_FRAGMENT_BASE64');
  }
});

test('fragments decoding to more than 1 MiB in total are rejected', async () => {
  const res = await check({
    size: 1024 * 1024,
    blockBytes: 1024 * 1024,
    blockHashes: trueHashes(1024 * 1024, 1024 * 1024),
    // Overlapping fragments keep each one in bounds but total 1.2 MiB decoded.
    fragments: [frag(0, 700 * 1024), frag(0, 528 * 1024)],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENTS_TOO_LARGE');
});

test('a size above 1 MiB is rejected', async () => {
  const res = await check({
    size: 1024 * 1024 + 1,
    blockBytes: 1,
    blockHashes: [],
    fragments: [],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'RESOURCE_TOO_LARGE');
});

test('a resource of exactly 1 MiB is accepted', async () => {
  const size = 1024 * 1024;
  const blockBytes = size;
  const res = await check({
    size,
    blockBytes,
    blockHashes: trueHashes(size, blockBytes),
    fragments: [frag(0, size)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().verified, [0]);
});

test('invalid scalar fields are rejected', async () => {
  const good = {
    size: 10,
    blockBytes: 5,
    blockHashes: trueHashes(10, 5),
    fragments: [],
  };
  // Everything here is caught by the strict JSON schema (FST_ERR_VALIDATION).
  for (const patch of [
    { size: -1 },
    { size: 1.5 },
    { size: '10' },
    { size: Number.MAX_SAFE_INTEGER + 1 },
    { blockBytes: 0 },
    { blockBytes: -5 },
    { blockBytes: '8' },
    { blockHashes: 'x' },
    { fragments: 'x' },
    { extra: 1 },
  ]) {
    const res = await check({ ...good, ...patch });
    assert.equal(res.statusCode, 400, `expected 400 for ${JSON.stringify(patch)}`);
  }
});

test('semantic limits enforced by the checker carry dedicated codes', async () => {
  const size = 1024 * 1024 + 1;
  const oversized = await check({ size, blockBytes: 1, blockHashes: [], fragments: [] });
  assert.equal(oversized.statusCode, 400);
  assert.equal(oversized.json().code, 'RESOURCE_TOO_LARGE');

  // The hash-count rule is semantic (depends on size/blockBytes arithmetic).
  const mismatch = await check({ size: 10, blockBytes: 5, blockHashes: [], fragments: [] });
  assert.equal(mismatch.statusCode, 400);
  assert.equal(mismatch.json().code, 'HASH_COUNT_MISMATCH');
});

test('missing required fields are rejected', async () => {
  const good = {
    size: 10,
    blockBytes: 5,
    blockHashes: trueHashes(10, 5),
    fragments: [],
  };
  for (const key of ['size', 'blockBytes', 'blockHashes', 'fragments']) {
    const payload = { ...good };
    delete payload[key];
    const res = await check(payload);
    assert.equal(res.statusCode, 400, `expected 400 when ${key} missing`);
  }
});

test('unknown fields inside fragments are rejected', async () => {
  const res = await check({
    size: 10,
    blockBytes: 10,
    blockHashes: trueHashes(10, 10),
    fragments: [{ start: 0, dataBase64: content(0, 10).toString('base64'), end: 9 }],
  });
  assert.equal(res.statusCode, 400);
});

test('block indices are returned ascending even when fragments arrive unordered', async () => {
  const res = await check({
    size: 30,
    blockBytes: 10,
    blockHashes: trueHashes(30, 10),
    fragments: [frag(20, 10), frag(0, 10)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 2]);
  assert.deepEqual(body.missing, [1]);
  assert.deepEqual(body.refetchRanges, [{ start: 10, end: 19 }]);
});
