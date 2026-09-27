import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from '../src/app.js';

const app = buildApp();
const url = '/cache-retention-plan';

function retentionPlan(payload) {
  return app.inject({
    method: 'POST',
    url,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });
}

test('retains the highest-value cached bytes within budget', async () => {
  // Cache merges to [0,299]; access weights give [50,99]=2, [100,149]=5,
  // [150,249]=3. Budget 120 takes [100,149] (50 bytes) then truncates the
  // weight-3 segment to [150,219]; the two selections are adjacent and merge.
  const res = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 199 },
      { start: 100, end: 299 },
    ],
    accesses: [
      { start: 50, end: 149, weight: 2 },
      { start: 100, end: 249, weight: 3 },
    ],
    budgetBytes: 120,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 100, end: 219 }]);
  assert.equal(body.retainedBytes, 120);
  assert.equal(body.unusedBytes, 0);
});

test('budget larger than the positive-value cache leaves unused bytes', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 199 },
      { start: 100, end: 299 },
    ],
    accesses: [
      { start: 50, end: 149, weight: 2 },
      { start: 100, end: 249, weight: 3 },
    ],
    budgetBytes: 500,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  // Only 200 cached bytes carry positive weight; adjacent spans merge.
  assert.deepEqual(body.retained, [{ start: 50, end: 249 }]);
  assert.equal(body.retainedBytes, 200);
  assert.equal(body.unusedBytes, 300);
});

test('overlapping cache intervals are counted once', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 99 },
      { start: 50, end: 149 },
    ],
    accesses: [{ start: 0, end: 149, weight: 1 }],
    budgetBytes: 1000,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 0, end: 149 }]);
  assert.equal(body.retainedBytes, 150);
  assert.equal(body.unusedBytes, 850);
});

test('overlapping accesses accumulate weight per byte', async () => {
  // Weights: [0,49]=1, [50,99]=3, [100,149]=2. Budget 60 takes [50,99]
  // (50 bytes) then 10 bytes of the weight-2 span; selections merge.
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 0, end: 149 }],
    accesses: [
      { start: 0, end: 99, weight: 1 },
      { start: 50, end: 149, weight: 2 },
    ],
    budgetBytes: 60,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 50, end: 109 }]);
  assert.equal(body.retainedBytes, 60);
  assert.equal(body.unusedBytes, 0);
});

test('equal weights are selected lowest offset first', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 9 },
      { start: 100, end: 109 },
    ],
    accesses: [
      { start: 0, end: 9, weight: 5 },
      { start: 100, end: 109, weight: 5 },
    ],
    budgetBytes: 15,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [
    { start: 0, end: 9 },
    { start: 100, end: 104 },
  ]);
  assert.equal(body.retainedBytes, 15);
  assert.equal(body.unusedBytes, 0);
});

test('cache bytes without any access weight are never retained', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 0, end: 99 }],
    accesses: [{ start: 0, end: 49, weight: 1 }],
    budgetBytes: 1000,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 0, end: 49 }]);
  assert.equal(body.retainedBytes, 50);
  assert.equal(body.unusedBytes, 950);
});

test('access bytes outside the cache are irrelevant', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 500, end: 509 }],
    accesses: [{ start: 0, end: 999, weight: 7 }],
    budgetBytes: 100,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 500, end: 509 }]);
  assert.equal(body.retainedBytes, 10);
  assert.equal(body.unusedBytes, 90);
});

test('empty cache retains nothing', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [],
    accesses: [{ start: 0, end: 99, weight: 3 }],
    budgetBytes: 100,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, []);
  assert.equal(body.retainedBytes, 0);
  assert.equal(body.unusedBytes, 100);
});

test('empty accesses retain nothing', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 0, end: 99 }],
    accesses: [],
    budgetBytes: 100,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, []);
  assert.equal(body.retainedBytes, 0);
  assert.equal(body.unusedBytes, 100);
});

test('zero budget retains nothing', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 0, end: 99 }],
    accesses: [{ start: 0, end: 99, weight: 1 }],
    budgetBytes: 0,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, []);
  assert.equal(body.retainedBytes, 0);
  assert.equal(body.unusedBytes, 0);
});

test('empty resource retains nothing', async () => {
  const res = await retentionPlan({ size: 0, cached: [], accesses: [], budgetBytes: 10 });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, []);
  assert.equal(body.retainedBytes, 0);
  assert.equal(body.unusedBytes, 10);
});

test('budget truncates inside an interval keeping the lowest offsets', async () => {
  const res = await retentionPlan({
    size: 1000,
    cached: [{ start: 0, end: 99 }],
    accesses: [{ start: 0, end: 99, weight: 5 }],
    budgetBytes: 30,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: 0, end: 29 }]);
  assert.equal(body.retainedBytes, 30);
  assert.equal(body.unusedBytes, 0);
});

test('adjacent selected intervals merge, disjoint ones stay separate', async () => {
  // Equal weights, adjacent cache intervals: the whole selection merges.
  const merged = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 9 },
      { start: 10, end: 19 },
    ],
    accesses: [
      { start: 0, end: 9, weight: 5 },
      { start: 10, end: 19, weight: 5 },
    ],
    budgetBytes: 20,
  });
  assert.equal(merged.statusCode, 200);
  assert.deepEqual(merged.json().retained, [{ start: 0, end: 19 }]);

  // Same weights with a gap: two separate retained intervals.
  const disjoint = await retentionPlan({
    size: 1000,
    cached: [
      { start: 0, end: 9 },
      { start: 100, end: 109 },
    ],
    accesses: [
      { start: 0, end: 9, weight: 5 },
      { start: 100, end: 109, weight: 5 },
    ],
    budgetBytes: 20,
  });
  assert.equal(disjoint.statusCode, 200);
  assert.deepEqual(disjoint.json().retained, [
    { start: 0, end: 9 },
    { start: 100, end: 109 },
  ]);
});

test('large offsets stay within safe-integer precision', async () => {
  const size = Number.MAX_SAFE_INTEGER;
  const res = await retentionPlan({
    size,
    cached: [{ start: size - 10, end: size - 1 }],
    accesses: [{ start: size - 10, end: size - 1, weight: 1 }],
    budgetBytes: 5,
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.deepEqual(body.retained, [{ start: size - 10, end: size - 6 }]);
  assert.equal(body.retainedBytes, 5);
  assert.equal(body.unusedBytes, 0);
});

test('non-integer or negative size is rejected', async () => {
  for (const size of [-1, 1.5, '1000', Number.MAX_SAFE_INTEGER + 1]) {
    const res = await retentionPlan({ size, cached: [], accesses: [], budgetBytes: 10 });
    assert.equal(res.statusCode, 400, `expected 400 for size=${size}`);
  }
});

test('budgetBytes must be a non-negative safe integer', async () => {
  for (const budgetBytes of [-1, 0.5, '100', Number.MAX_SAFE_INTEGER + 1]) {
    const res = await retentionPlan({ size: 100, cached: [], accesses: [], budgetBytes });
    assert.equal(res.statusCode, 400, `expected 400 for budgetBytes=${budgetBytes}`);
  }
});

test('cached must be an array of interval objects', async () => {
  for (const cached of [null, {}, '0-9', [null], [1], [['0', '9']], [{ start: 0 }], [{ start: 0, end: 9, extra: 1 }]]) {
    const res = await retentionPlan({ size: 100, cached, accesses: [], budgetBytes: 10 });
    assert.equal(res.statusCode, 400, `expected 400 for cached=${JSON.stringify(cached)}`);
  }
});

test('cached interval boundaries must be non-negative safe integers', async () => {
  for (const interval of [
    { start: -1, end: 9 },
    { start: 0, end: -1 },
    { start: 0.5, end: 9 },
    { start: 0, end: 9.5 },
    { start: '0', end: 9 },
  ]) {
    const res = await retentionPlan({ size: 100, cached: [interval], accesses: [], budgetBytes: 10 });
    assert.equal(res.statusCode, 400, `expected 400 for ${JSON.stringify(interval)}`);
  }
});

test('cached interval with start after end is rejected', async () => {
  const res = await retentionPlan({
    size: 100,
    cached: [{ start: 50, end: 10 }],
    accesses: [],
    budgetBytes: 10,
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'INVALID_CACHED_RANGE');
});

test('cached interval reaching past the resource end is rejected', async () => {
  const res = await retentionPlan({
    size: 100,
    cached: [{ start: 90, end: 100 }],
    accesses: [],
    budgetBytes: 10,
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().code, 'CACHED_RANGE_OUT_OF_BOUNDS');
});

test('cached is limited to 1000 intervals', async () => {
  const cached = Array.from({ length: 1001 }, () => ({ start: 0, end: 0 }));
  const res = await retentionPlan({ size: 100, cached, accesses: [], budgetBytes: 10 });
  assert.equal(res.statusCode, 400);
});

test('accesses must be an array of weighted interval objects', async () => {
  for (const accesses of [
    null,
    {},
    '0-9',
    [null],
    [1],
    [{ start: 0, end: 9 }],
    [{ start: 0, end: 9, weight: 1, extra: 1 }],
  ]) {
    const res = await retentionPlan({ size: 100, cached: [], accesses, budgetBytes: 10 });
    assert.equal(res.statusCode, 400, `expected 400 for accesses=${JSON.stringify(accesses)}`);
  }
});

test('access weight must be a positive integer within the cap', async () => {
  for (const weight of [0, -1, 1.5, '5', 1_000_001, Number.MAX_SAFE_INTEGER]) {
    const res = await retentionPlan({
      size: 100,
      cached: [],
      accesses: [{ start: 0, end: 9, weight }],
      budgetBytes: 10,
    });
    assert.equal(res.statusCode, 400, `expected 400 for weight=${weight}`);
  }
  // The cap itself is accepted.
  const ok = await retentionPlan({
    size: 100,
    cached: [{ start: 0, end: 9 }],
    accesses: [{ start: 0, end: 9, weight: 1_000_000 }],
    budgetBytes: 10,
  });
  assert.equal(ok.statusCode, 200);
  assert.equal(ok.json().retainedBytes, 10);
});

test('access interval out of bounds or reversed is rejected', async () => {
  const outOfBounds = await retentionPlan({
    size: 100,
    cached: [],
    accesses: [{ start: 90, end: 100, weight: 1 }],
    budgetBytes: 10,
  });
  assert.equal(outOfBounds.statusCode, 400);
  assert.equal(outOfBounds.json().code, 'ACCESS_RANGE_OUT_OF_BOUNDS');

  const reversed = await retentionPlan({
    size: 100,
    cached: [],
    accesses: [{ start: 50, end: 10, weight: 1 }],
    budgetBytes: 10,
  });
  assert.equal(reversed.statusCode, 400);
  assert.equal(reversed.json().code, 'INVALID_ACCESS_RANGE');
});

test('accesses are limited to 1000 intervals', async () => {
  const accesses = Array.from({ length: 1001 }, () => ({ start: 0, end: 0, weight: 1 }));
  const res = await retentionPlan({ size: 100, cached: [], accesses, budgetBytes: 10 });
  assert.equal(res.statusCode, 400);
});

test('missing required fields are rejected by schema validation', async () => {
  for (const payload of [
    {},
    { size: 100 },
    { size: 100, cached: [] },
    { size: 100, cached: [], accesses: [] },
  ]) {
    const res = await retentionPlan(payload);
    assert.equal(res.statusCode, 400, `expected 400 for ${JSON.stringify(payload)}`);
  }
});

test('extra fields are rejected by schema validation', async () => {
  const res = await retentionPlan({
    size: 100,
    cached: [],
    accesses: [],
    budgetBytes: 10,
    extra: 1,
  });
  assert.equal(res.statusCode, 400);
});

test('error responses carry the shared error shape', async () => {
  const res = await retentionPlan({
    size: 100,
    cached: [{ start: 5, end: 1 }],
    accesses: [],
    budgetBytes: 10,
  });
  assert.equal(res.statusCode, 400);
  const body = res.json();
  assert.equal(body.statusCode, 400);
  assert.equal(body.error, 'Bad Request');
  assert.equal(typeof body.code, 'string');
  assert.equal(typeof body.message, 'string');
});

test('existing endpoints are unaffected', async () => {
  const plan = await app.inject({
    method: 'POST',
    url: '/plan',
    headers: { Range: 'bytes=0-99', 'content-type': 'application/json' },
    payload: JSON.stringify({ size: 10000 }),
  });
  assert.equal(plan.statusCode, 206);
  assert.equal(plan.json().segmentsCount, 1);

  const resume = await app.inject({
    method: 'POST',
    url: '/resume-plan',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ size: 100, completed: [], chunkBytes: 10, limit: 1 }),
  });
  assert.equal(resume.statusCode, 200);
  assert.equal(resume.json().requestsCount, 1);
});
