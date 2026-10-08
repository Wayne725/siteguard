const {test} = require('node:test');
const assert = require('node:assert/strict');
const {OrderIntent, mount} = require('./ui.js');

const run_a = 'aaaaaaaaaaaaaaaa', run_b = 'bbbbbbbbbbbbbbbb';
function memory_storage() {
  const values = new Map();
  return {getItem: key => values.get(key) || null,
          setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key)};
}

function fake_document() {
  const elements = new Map();
  return {getElementById(id) {
    if (!elements.has(id)) elements.set(id, {value: '1', disabled: false, hidden: false, textContent: ''});
    return elements.get(id);
  }};
}

test('lost acknowledgement preserves the product and key through actual click retries', async () => {
  const document = fake_document(), payloads = [], committed = new Set();
  let health_calls = 0, order_calls = 0, id_count = 0;
  const fetch_request = async (path, options) => {
    if (path === '/health') {
      health_calls += 1;
      return new Response(JSON.stringify({ready: true, lab_id: 'local-resource-defense-lab-v1',
        run_id: run_a, backend: 'sqlite', app_mode: 'fixed'}),
        {headers: {'X-Lab-Gateway-Mode': 'adaptive'}});
    }
    const payload = JSON.parse(options.body);
    payloads.push(payload);
    committed.add(payload.request_id);
    if (order_calls++ === 0) throw new Error('lost acknowledgement after commit');
    return new Response(JSON.stringify({ok: true, persisted: true, order_id: payload.request_id}));
  };
  await mount(document, fetch_request, memory_storage(), () => `intent-${++id_count}`);
  assert.match(document.getElementById('status').textContent, /後端模式 fixed · Envoy adaptive/);
  document.getElementById('product_id').value = '3';
  await document.getElementById('orders').onclick();
  assert.equal(document.getElementById('product_id').disabled, true);
  assert.match(document.getElementById('orders_result').textContent, /原鍵重試/);
  document.getElementById('product_id').value = '9';
  await document.getElementById('orders').onclick();
  assert.deepEqual(payloads[0], payloads[1]);
  assert.equal(payloads[1].product_id, 3);
  assert.equal(payloads[1].expected_run_id, run_a);
  assert.equal(committed.size, 1);
  assert.equal(document.getElementById('product_id').disabled, false);
  await document.getElementById('orders').onclick();
  assert.notEqual(payloads[2].request_id, payloads[1].request_id);
  assert.equal(committed.size, 2);
  assert.equal(health_calls, 1);
});

test('reload restores a pending intent and a reset requires explicit new-run acknowledgement', () => {
  const storage = memory_storage();
  const first = new OrderIntent(storage, () => 'same-key');
  first.set_run(run_a);
  const original = first.payload(4);
  const reloaded = new OrderIntent(storage, () => 'new-key');
  reloaded.set_run(run_a);
  assert.deepEqual(reloaded.payload(7), original);
  reloaded.set_run(run_b);
  assert.equal(reloaded.stale, true);
  assert.throws(() => reloaded.payload(7), /實驗已重設/);
  reloaded.start_new_run();
  assert.deepEqual(reloaded.payload(7), {request_id: 'new-key', product_id: 7, expected_run_id: run_b});
});

test('only a matching persisted acknowledgement completes the intent', () => {
  const intent = new OrderIntent(memory_storage(), () => 'key-1');
  intent.set_run(run_a);
  const original = intent.payload(1);
  assert.equal(intent.acknowledge({ok: true}), false);
  assert.equal(intent.acknowledge({ok: true, persisted: true, order_id: 'wrong-key'}), false);
  assert.deepEqual(intent.payload(2), original);
  assert.equal(intent.acknowledge({ok: true, persisted: true, order_id: 'key-1'}), true);
  assert.equal(intent.pending, null);
});

test('storage denied still permits safe same-page retries and exposes persistence limitation', () => {
  const intent = new OrderIntent(null, () => 'temporary-key');
  intent.set_run(run_a);
  const original = intent.payload(2);
  assert.equal(intent.storage_available, false);
  assert.deepEqual(intent.payload(3), original);
});
