/* Independent Node HTTP origin; loopback-only and without npm dependencies. */
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { Worker, isMainThread, parentPort } = require('node:worker_threads');

const HOST = '127.0.0.1';
const PORT = 18101;
const BODY_LIMIT = 1024 * 1024;
const WORKERS = 4;
const MAX_OUTSTANDING = 24;
const HEAVY_MS = 350;
const RANGE_BODY = Buffer.from(Array.from({ length: 32768 }, (_, index) => index % 256));
const now = () => Number(process.hrtime.bigint()) / 1e9;
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

if (!isMainThread) {
  parentPort.on('message', ({ kind, requestId, queuedAt }) => {
    const startedAt = now();
    if (kind === 'heavy') {
      while ((now() - startedAt) * 1000 < HEAVY_MS) {
        crypto.pbkdf2Sync('bounded-fixture-work', 'fixed-salt', 3000, 32, 'sha256');
      }
    }
    parentPort.postMessage({ kind, requestId, queuedAt, startedAt, endedAt: now() });
  });
} else {
  if (process.argv.length > 2) {
    process.stderr.write('This fixture takes no options and binds only 127.0.0.1:18101.\n');
    process.exit(2);
  }

  const state = {
    available: true, outstanding: 0, running: 0, peakRunning: 0,
    orders: Object.create(null), postAttempts: Object.create(null), postExecutions: Object.create(null), workerRecords: [],
  };
  const jobs = [];
  const workers = Array.from({ length: WORKERS }, () => {
    const worker = new Worker(__filename);
    const slot = { worker, job: null };
    worker.on('message', ({ kind, requestId, queuedAt, startedAt, endedAt }) => {
      const job = slot.job;
      state.running -= 1;
      state.outstanding -= 1;
      state.workerRecords.push({
        kind, request_id: requestId, queue_ms: Math.round((startedAt - queuedAt) * 1e6) / 1000,
        started_at: startedAt, ended_at: endedAt,
      });
      let result = { ok: true, kind };
      if (kind === 'orders') {
        state.postExecutions[requestId] = (state.postExecutions[requestId] || 0) + 1;
        state.orders[requestId] ??= { order_id: requestId, quantity: 1 };
        result = { ok: true, persisted: true, ...state.orders[requestId] };
      }
      slot.job = null;
      job.resolve(result);
      dispatch();
    });
    worker.on('error', (error) => {
      if (slot.job) {
        state.running -= 1;
        state.outstanding -= 1;
        slot.job.reject(error);
        slot.job = null;
      }
      state.available = false;
      while (jobs.length) {
        state.outstanding -= 1;
        jobs.shift().reject(error);
      }
    });
    return slot;
  });

  function dispatch() {
    for (const slot of workers) {
      if (slot.job || !jobs.length) continue;
      slot.job = jobs.shift();
      state.running += 1;
      state.peakRunning = Math.max(state.peakRunning, state.running);
      const { kind, requestId, queuedAt } = slot.job;
      slot.worker.postMessage({ kind, requestId, queuedAt });
    }
  }

  function submit(kind, requestId) {
    if (state.outstanding >= MAX_OUTSTANDING) return null;
    state.outstanding += 1;
    return new Promise((resolve, reject) => {
      jobs.push({ kind, requestId, queuedAt: now(), resolve, reject });
      dispatch();
    });
  }

  function snapshot() {
    return {
      fixture: 'siteguard-loopback-v1', implementation: 'node', node_version: process.version,
      available: state.available, workers: WORKERS, outstanding: state.outstanding,
      running: state.running, peak_running: state.peakRunning,
      orders: state.orders, post_attempts: state.postAttempts, worker_records: state.workerRecords,
      post_executions: state.postExecutions,
    };
  }

  function reply(req, res, status, body = Buffer.alloc(0), headers = {}) {
    if (!Buffer.isBuffer(body)) body = Buffer.from(JSON.stringify(body));
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': body.length, ...headers });
    res.end(req.method === 'HEAD' ? undefined : body);
  }

  function multipartParts(body, contentType) {
    const match = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
    if (!match) return [];
    const delimiter = Buffer.from(`--${match[1] || match[2]}`);
    const parts = [];
    let cursor = body.indexOf(delimiter);
    while (cursor >= 0) {
      cursor += delimiter.length;
      if (body.subarray(cursor, cursor + 2).equals(Buffer.from('--'))) break;
      cursor += 2;
      const headerEnd = body.indexOf('\r\n\r\n', cursor);
      const next = body.indexOf(delimiter, headerEnd + 4);
      if (headerEnd < 0 || next < 0) break;
      const partHeaders = body.subarray(cursor, headerEnd).toString('latin1');
      const content = body.subarray(headerEnd + 4, next - 2);
      parts.push({
        name: partHeaders.match(/(?:^|[;\s])name="([^"]*)"/i)?.[1] || null,
        filename: partHeaders.match(/filename="([^"]*)"/i)?.[1] || null,
        size: content.length, sha256: digest(content),
      });
      cursor = next;
    }
    return parts;
  }

  async function route(req, res, body) {
    const url = new URL(req.url, `http://${HOST}:${PORT}`);
    const path = decodeURIComponent(url.pathname);
    if (path === '/fixture/state') return reply(req, res, 200, snapshot());
    if (path === '/fixture/reset' && req.method === 'POST') {
      if (state.outstanding) return reply(req, res, 409, { error: 'wait_for_drain' });
      state.orders = Object.create(null);
      state.postAttempts = Object.create(null);
      state.postExecutions = Object.create(null);
      state.workerRecords = [];
      state.peakRunning = 0;
      return reply(req, res, 200, { ok: true });
    }
    if ((path === '/fixture/availability' || path === '/fixture/control') && req.method === 'POST') {
      const { available } = JSON.parse(body);
      if (typeof available !== 'boolean') return reply(req, res, 400, { error: 'boolean_required' });
      state.available = available;
      return reply(req, res, 200, { available });
    }
    if (!state.available) {
      return reply(req, res, 503, { error: 'origin_temporarily_unavailable' }, { 'Retry-After': '1' });
    }
    if (path === '/health') {
      return reply(req, res, 200, { fixture: 'siteguard-loopback-v1', implementation: 'node', ready: true });
    }
    if (path === '/') {
      return reply(req, res, 200, Buffer.from('<!doctype html><title>測試網站</title><p>正常頁面</p>'),
        { 'Content-Type': 'text/html; charset=utf-8' });
    }
    if (path === '/echo' || path === '/中文/頁面') {
      const query = Object.create(null);
      for (const [key, value] of url.searchParams) (query[key] ??= []).push(value);
      return reply(req, res, 200, {
        method: req.method, path, query, authorization: req.headers.authorization || null,
        cookie: req.headers.cookie || null, content_type: req.headers['content-type'] || null,
        body: body.toString('utf8'), x_test: req.headers['x-test'] || null,
        forwarded_headers: Object.fromEntries(Object.entries(req.headers).filter(([name]) =>
          name.startsWith('x-envoy-') || ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
            'x-real-ip', 'forwarded'].includes(name))),
      }, { 'Set-Cookie': 'fixture_cookie=ok; Path=/; HttpOnly; SameSite=Lax' });
    }
    if (path === '/redirect') {
      return reply(req, res, 302, Buffer.alloc(0), { Location: '/destination?from=redirect' });
    }
    if (path === '/destination') return reply(req, res, 200, { destination: true });
    if (path === '/cache') {
      const matched = req.headers['if-none-match'] === '"fixture-v1"';
      return reply(req, res, matched ? 304 : 200, matched ? Buffer.alloc(0) : Buffer.from('cache-body'), {
        ETag: '"fixture-v1"', 'Cache-Control': 'public, max-age=60', 'Content-Type': 'text/plain',
      });
    }
    if (path === '/range') {
      if (!req.headers.range) {
        return reply(req, res, 200, RANGE_BODY, { 'Content-Type': 'application/octet-stream', 'Accept-Ranges': 'bytes' });
      }
      if (req.headers.range !== 'bytes=100-199') {
        return reply(req, res, 416, Buffer.alloc(0), { 'Content-Range': `bytes */${RANGE_BODY.length}` });
      }
      return reply(req, res, 206, RANGE_BODY.subarray(100, 200), {
        'Content-Type': 'application/octet-stream', 'Content-Range': `bytes 100-199/${RANGE_BODY.length}`,
        'Accept-Ranges': 'bytes',
      });
    }
    if (path === '/upload' && req.method === 'POST') {
      return reply(req, res, 200, { body_bytes: body.length, parts: multipartParts(body, req.headers['content-type'] || '') });
    }
    if (path === '/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no' });
      res.write('event: first\ndata: immediately\n\n');
      const timer = setTimeout(() => res.end('event: second\ndata: later\n\n'), 700);
      res.on('close', () => clearTimeout(timer));
      return;
    }
    if (path === '/ws') return reply(req, res, 400, { error: 'websocket_upgrade_required' });
    if (path === '/delay') {
      const milliseconds = Number(url.searchParams.get('ms') ?? 700);
      if (!Number.isInteger(milliseconds) || milliseconds < 0 || milliseconds > 1500) {
        return reply(req, res, 400, { error: 'delay_out_of_bounds' });
      }
      const timer = setTimeout(() => reply(req, res, 200, { ok: true, delay_ms: milliseconds }), milliseconds);
      res.on('close', () => clearTimeout(timer));
      return;
    }
    if (path === '/orders' || path === '/heavy') {
      let requestId = req.headers['x-request-id'] || '';
      if (path === '/orders') {
        if (req.method !== 'POST') return reply(req, res, 405, { error: 'POST_required' });
        requestId = JSON.parse(body).request_id;
        if (typeof requestId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(requestId)) {
          return reply(req, res, 400, { error: 'request_id_required' });
        }
        state.postAttempts[requestId] = (state.postAttempts[requestId] || 0) + 1;
      }
      const work = submit(path === '/orders' ? 'orders' : 'heavy', requestId);
      if (!work) return reply(req, res, 503, { error: 'fixture_capacity' });
      return reply(req, res, 200, await work);
    }
    return reply(req, res, 404, { error: 'not_found' });
  }

  function wsFrame(opcode, payload) {
    const prefix = payload.length < 126 ? Buffer.from([0x80 | opcode, payload.length]) : Buffer.alloc(4);
    if (payload.length >= 126) {
      prefix[0] = 0x80 | opcode;
      prefix[1] = 126;
      prefix.writeUInt16BE(payload.length, 2);
    }
    return Buffer.concat([prefix, payload]);
  }

  const sockets = new Set();
  const server = http.createServer((req, res) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        if (!res.headersSent) reply(req, res, 413, { error: 'fixture_body_limit' });
        req.destroy();
      } else chunks.push(chunk);
    });
    req.on('end', () => {
      if (size > BODY_LIMIT) return;
      route(req, res, Buffer.concat(chunks)).catch((error) => {
        if (!res.headersSent) reply(req, res, error instanceof SyntaxError ? 400 : 500, { error: error.name });
        else res.destroy();
      });
    });
    req.on('error', () => res.destroy());
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.on('upgrade', (req, socket, head) => {
    if (req.url !== '/ws' || !state.available || !req.headers['sec-websocket-key']) {
      socket.end(`HTTP/1.1 ${state.available ? '400 Bad Request' : '503 Service Unavailable'}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
      return;
    }
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] +
      '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.setTimeout(3500, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    let buffer = head;
    let frames = 0;
    function consume(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 131072) return socket.destroy();
      while (buffer.length >= 2 && frames < 8) {
        const first = buffer[0];
        const masked = Boolean(buffer[1] & 0x80);
        let length = buffer[1] & 0x7f;
        let cursor = 2;
        if (!(first & 0x80) || first & 0x70 || !masked) return socket.destroy();
        if (length === 126) {
          if (buffer.length < 4) return;
          length = buffer.readUInt16BE(2);
          cursor = 4;
        } else if (length === 127) return socket.destroy();
        if (buffer.length < cursor + 4 + length) return;
        const mask = buffer.subarray(cursor, cursor + 4);
        cursor += 4;
        const payload = Buffer.from(buffer.subarray(cursor, cursor + length));
        for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
        buffer = buffer.subarray(cursor + length);
        const opcode = first & 0x0f;
        if (![1, 2, 8, 9].includes(opcode)) return socket.destroy();
        socket.write(wsFrame(opcode === 9 ? 10 : opcode, payload));
        frames += 1;
        if (opcode === 8) return socket.end();
      }
    }
    socket.on('data', consume);
    if (head.length) consume(Buffer.alloc(0));
  });

  let stopping = false;
  async function stop() {
    if (stopping) return;
    stopping = true;
    server.close();
    for (const socket of sockets) socket.destroy();
    await Promise.all(workers.map(({ worker }) => worker.terminate()));
  }
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  server.on('error', async (error) => {
    process.stderr.write(`${error.code}: Node fixture could not bind ${HOST}:${PORT}\n`);
    await stop();
    process.exitCode = 1;
  });
  server.listen(PORT, HOST, () => process.stdout.write(`Owned Node fixture listening on http://${HOST}:${PORT}\n`));
}
