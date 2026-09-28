import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { checkCacheIntegrity } from '../src/cache-integrity.js';

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
// o % 251, so any span's digest is reproducible.
function span(start, length) {
  const buffer = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) buffer[i] = (start + i) % 251;
  return buffer;
}

const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
const fragment = (start, length) => ({ start, dataBase64: span(start, length).toString('base64') });

// Build the correct digest list for a resource of `size` covered by `blocks`.
function manifest(size, blocks, mutate = {}) {
  const blockBytes = Math.ceil(size / blocks);
  const digests = [];
  for (let i = 0; i < blocks; i += 1) {
    const start = i * blockBytes;
    const end = Math.min(start + blockBytes, size);
    digests[i] = mutate[i] ?? sha(span(start, end - start));
  }
  return { size, blockBytes, digests };
}

test('a fully cached resource with matching digests is all verified', async () => {
  const res = await check({ ...manifest(1000, 10), fragments: [fragment(0, 1000)] });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), {
    statusCode: 200,
    blocksCount: 10,
    verified: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    missing: [],
    corrupt: [],
    refetchRanges: [],
  });
});

test('a size not divisible by blockBytes gives a shorter final block', async () => {
  // 1000 / 128 -> 8 blocks; the last one is 104 bytes.
  const res = await check({ ...manifest(1000, 8), fragments: [fragment(0, 1000)] });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.blocksCount, 8);
  assert.deepEqual(body.verified, [0, 1, 2, 3, 4, 5, 6, 7]);
});

test('uncovered blocks are missing and merged into refetch ranges', async () => {
  // 100-byte blocks; cache covers blocks 0-1 and 5-9, leaving 2,3,4 missing.
  const res = await check({
    ...manifest(1000, 10),
    fragments: [fragment(0, 200), fragment(500, 500)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 1, 5, 6, 7, 8, 9]);
  assert.deepEqual(body.missing, [2, 3, 4]);
  assert.deepEqual(body.corrupt, []);
  assert.deepEqual(body.refetchRanges, [{ start: 200, end: 499 }]);
});

test('refetch ranges stay split around a verified block', async () => {
  // Block 3 has a wrong digest (corrupt), block 1 and blocks 5-9 are
  // uncovered (missing), blocks 0,2,4 verify. Ranges stay disjoint because
  // verified block 4 separates the corrupt block 3 from the missing tail.
  const wrong = 'a'.repeat(64);
  const res = await check({
    ...manifest(1000, 10, { 3: wrong }),
    fragments: [fragment(0, 100), fragment(200, 300)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 2, 4]);
  assert.deepEqual(body.missing, [1, 5, 6, 7, 8, 9]);
  assert.deepEqual(body.corrupt, [3]);
  assert.deepEqual(body.refetchRanges, [
    { start: 100, end: 199 },
    { start: 300, end: 399 },
    { start: 500, end: 999 },
  ]);
});

test('adjacent missing and corrupt blocks merge into one refetch range', async () => {
  // Blocks 2 and 3 fully cached, but block 2 has a wrong digest; blocks 0-1
  // are uncovered. [0,199] and [200,299] are adjacent and merge.
  const wrong = 'a'.repeat(64);
  const res = await check({
    ...manifest(1000, 10, { 2: wrong }),
    fragments: [fragment(200, 300)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.corrupt, [2]);
  assert.deepEqual(body.verified, [3, 4]);
  assert.deepEqual(body.missing, [0, 1, 5, 6, 7, 8, 9]);
  assert.deepEqual(body.refetchRanges, [
    { start: 0, end: 299 },
    { start: 500, end: 999 },
  ]);
});

test('a fully covered block with a mismatching digest is corrupt', async () => {
  const wrong = 'f'.repeat(64);
  const res = await check({
    ...manifest(100, 4, { 2: wrong }),
    fragments: [fragment(0, 100)],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0, 1, 3]);
  assert.deepEqual(body.missing, []);
  assert.deepEqual(body.corrupt, [2]);
  assert.deepEqual(body.refetchRanges, [{ start: 50, end: 74 }]);
});

test('a partial block is missing even when the present bytes hash-match', async () => {
  // 25-byte blocks: the cache covers all of block 0 and 15 of block 1's
  // 25 bytes, leaving block 1 partial and blocks 2-3 uncovered.
  const res = await check({ ...manifest(100, 4), fragments: [fragment(0, 40)] });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.verified, [0]);
  assert.deepEqual(body.missing, [1, 2, 3]);
  assert.deepEqual(body.refetchRanges, [{ start: 25, end: 99 }]);
});

test('overlapping identical fragments coexist and verify', async () => {
  const res = await check({
    ...manifest(1000, 10),
    fragments: [fragment(0, 300), fragment(200, 800)],
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().verified, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
});

test('overlapping fragments that disagree mark every touched block corrupt', async () => {
  const good = span(0, 300);
  // Second fragment overlaps [200,299] and disagrees at absolute 250-260.
  const evil = span(200, 200);
  for (let i = 50; i <= 60; i += 1) evil[i] = (evil[i] + 1) % 256;
  const res = await check({
    ...manifest(1000, 10),
    fragments: [
      { start: 0, dataBase64: good.toString('base64') },
      { start: 200, dataBase64: evil.toString('base64') },
    ],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  // Conflict [250,260] lies entirely inside block 2; blocks 0-2 are fully
  // covered (0,1 verified) and blocks 4-9 uncovered.
  assert.deepEqual(body.corrupt, [2]);
  assert.deepEqual(body.missing, [4, 5, 6, 7, 8, 9]);
  assert.deepEqual(body.verified, [0, 1, 3]);
  assert.deepEqual(body.refetchRanges, [
    { start: 200, end: 299 },
    { start: 400, end: 999 },
  ]);
});

test('a conflict poisons every block the conflict interval spans', async () => {
  // Disagreement [190,210] crosses the boundary between blocks 1 and 2.
  const good = span(0, 400);
  const evil = span(190, 30);
  for (let i = 0; i <= 20; i += 1) evil[i] = (evil[i] + 1) % 256;
  const res = await check({
    ...manifest(1000, 10),
    fragments: [
      { start: 0, dataBase64: good.toString('base64') },
      { start: 190, dataBase64: evil.toString('base64') },
    ],
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.corrupt, [1, 2]);
  assert.deepEqual(body.missing, [4, 5, 6, 7, 8, 9]);
  assert.deepEqual(body.verified, [0, 3]);
  assert.deepEqual(body.refetchRanges, [
    { start: 100, end: 299 },
    { start: 400, end: 999 },
  ]);
});

test('adjacent fragments cover blocks without gaps', async () => {
  const res = await check({
    ...manifest(1000, 10),
    fragments: [
      fragment(0, 250),
      fragment(250, 250),
      fragment(500, 250),
      fragment(750, 250),
    ],
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().verified.length, 10);
});

test('a block larger than the resource yields a single block', async () => {
  const res = await check({ ...manifest(10, 1), fragments: [fragment(0, 10)] });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.blocksCount, 1);
  assert.deepEqual(body.verified, [0]);
});

test('an empty resource returns empty results', async () => {
  const res = await check({ size: 0, blockBytes: 64, digests: [], fragments: [] });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json(), {
    statusCode: 200,
    blocksCount: 0,
    verified: [],
    missing: [],
    corrupt: [],
    refetchRanges: [],
  });
});

test('an empty resource accepts blockBytes of any positive size', async () => {
  const res = await check({ size: 0, blockBytes: 1, digests: [], fragments: [] });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().blocksCount, 0);
});

test('digest count must equal ceil(size/blockBytes)', async () => {
  const res = await check({ size: 100, blockBytes: 64, digests: [sha(span(0, 64))], fragments: [] });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'INVALID_DIGEST_COUNT');
});

test('an extra digest is rejected', async () => {
  const res = await check({
    size: 100,
    blockBytes: 100,
    digests: [sha(span(0, 100)), sha(span(0, 1))],
    fragments: [],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'INVALID_DIGEST_COUNT');
});

test('a non-array digests field is rejected', async () => {
  const res = await check({ size: 100, blockBytes: 100, digests: sha(span(0, 100)), fragments: [] });
  assert.equal(res.statusCode, 400);
});

test('digests must be lowercase 64-character hexadecimal', async () => {
  const good = sha(span(0, 100));
  for (const digest of [
    good.toUpperCase(),
    `${good.slice(0, -1)}g`,
    good.slice(0, -1),
    `${good}00`,
    'not hex at all',
  ]) {
    const res = await check({ size: 100, blockBytes: 100, digests: [digest], fragments: [] });
    assert.equal(res.statusCode, 400, `expected 400 for digest=${digest}`);
  }
});

test('size must be a non-negative safe integer', async () => {
  for (const size of [-1, 0.5, '1000', Number.MAX_SAFE_INTEGER + 1, null]) {
    const res = await check({ size, blockBytes: 64, digests: [], fragments: [] });
    assert.equal(res.statusCode, 400, `expected 400 for size=${size}`);
  }
});

test('blockBytes must be a positive safe integer', async () => {
  for (const blockBytes of [0, -1, 0.5, '64', Number.MAX_SAFE_INTEGER + 1]) {
    const res = await check({ size: 100, blockBytes, digests: [], fragments: [] });
    assert.equal(res.statusCode, 400, `expected 400 for blockBytes=${blockBytes}`);
  }
});

test('a resource larger than 1 MiB is rejected', async () => {
  const res = await check({
    size: 1024 * 1024 + 1,
    blockBytes: 64,
    digests: [],
    fragments: [],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'RESOURCE_TOO_LARGE');
});

test('a resource of exactly 1 MiB is accepted', async () => {
  const size = 1024 * 1024;
  const res = await check({
    ...manifest(size, 1),
    fragments: [fragment(0, size)],
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().blocksCount, 1);
  assert.deepEqual(res.json().verified, [0]);
});

test('a fragment extending past the resource end is rejected', async () => {
  const res = await check({
    ...manifest(100, 1),
    fragments: [fragment(0, 10), fragment(90, 20)],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENT_OUT_OF_BOUNDS');
});

test('malformed base64 fragments are rejected', async () => {
  for (const dataBase64 of ['####', 'QR==', 'QQ==QQ==', 'Q Q==']) {
    const res = await check({ ...manifest(100, 1), fragments: [{ start: 0, dataBase64 }] });
    assert.equal(res.statusCode, 400, `expected 400 for dataBase64=${dataBase64}`);
    assert.equal(res.json().code, 'INVALID_FRAGMENT_BASE64');
  }
});

test('fragment start must be a non-negative safe integer', async () => {
  const dataBase64 = span(0, 1).toString('base64');
  for (const start of [-1, 0.5, '0', Number.MAX_SAFE_INTEGER + 1, null]) {
    const res = await check({ ...manifest(100, 1), fragments: [{ start, dataBase64 }] });
    assert.equal(res.statusCode, 400, `expected 400 for start=${start}`);
  }
});

test('overlapping fragments over 1 MiB decoded total are rejected', async () => {
  // Two overlapping 600 KiB fragments on a 1 MiB resource decode to 1.2 MiB.
  const size = 1024 * 1024;
  const res = await check({
    ...manifest(size, 2),
    fragments: [
      { start: 0, dataBase64: span(0, 600 * 1024).toString('base64') },
      { start: 400 * 1024, dataBase64: span(400 * 1024, 600 * 1024).toString('base64') },
    ],
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'FRAGMENTS_TOO_LARGE');
});

test('more than 1024 fragments are rejected by the schema', async () => {
  const res = await check({
    ...manifest(100, 1),
    fragments: Array.from({ length: 1025 }, (_, i) => ({
      start: i % 100,
      dataBase64: span(i % 100, 1).toString('base64'),
    })),
  });
  assert.equal(res.statusCode, 400);
});

test('the decoder enforces the fragment cap and non-array shape directly', () => {
  const tooMany = checkCacheIntegrity({
    size: 100,
    blockBytes: 100,
    digests: [sha(span(0, 100))],
    fragments: Array.from({ length: 1025 }, (_, i) => ({
      start: i % 100,
      dataBase64: span(i % 100, 1).toString('base64'),
    })),
  });
  assert.equal(tooMany.statusCode, 400);
  assert.equal(tooMany.code, 'TOO_MANY_FRAGMENTS');

  const notArray = checkCacheIntegrity({
    size: 100,
    blockBytes: 100,
    digests: [sha(span(0, 100))],
    fragments: null,
  });
  assert.equal(notArray.statusCode, 400);
  assert.equal(notArray.code, 'INVALID_FRAGMENTS');
});

test('unknown fields are rejected at the top level and inside items', async () => {
  const base = { ...manifest(100, 1), fragments: [fragment(0, 100)] };
  for (const payload of [
    { ...base, extra: 1 },
    { ...base, fragments: [{ ...base.fragments[0], end: 99 }] },
  ]) {
    const res = await check(payload);
    assert.equal(res.statusCode, 400);
  }
});

test('missing required fields are rejected', async () => {
  const full = { ...manifest(100, 1), fragments: [fragment(0, 100)] };
  for (const key of ['size', 'blockBytes', 'digests', 'fragments']) {
    const payload = { ...full };
    delete payload[key];
    const res = await check(payload);
    assert.equal(res.statusCode, 400, `expected 400 when ${key} missing`);
  }
});
