const intent_storage_key = 'local-resource-defense-order-intent-v1';

class OrderIntent {
  constructor(storage, new_id) {
    this.storage = storage;
    this.new_id = new_id;
    this.run_id = null;
    this.pending = null;
    this.storage_available = true;
    try {
      const saved = JSON.parse(storage.getItem(intent_storage_key));
      if (saved && /^[a-zA-Z0-9_-]{1,80}$/.test(saved.request_id) &&
          /^[a-f0-9]{16}$/.test(saved.expected_run_id) &&
          Number.isInteger(saved.product_id) && saved.product_id >= 1 && saved.product_id <= 20) {
        this.pending = saved;
      }
    } catch { this.storage_available = false; }
  }

  set_run(run_id) { this.run_id = run_id; }

  get stale() {
    return Boolean(this.pending && this.run_id && this.pending.expected_run_id !== this.run_id);
  }

  save() {
    try {
      if (this.pending) this.storage.setItem(intent_storage_key, JSON.stringify(this.pending));
      else this.storage.removeItem(intent_storage_key);
    } catch { this.storage_available = false; }
  }

  payload(product_id) {
    if (!this.run_id) throw new Error('請先讀取實驗狀態。');
    if (this.stale) throw new Error('實驗已重設；舊訂單不能送往新實驗。');
    if (!this.pending) {
      if (!Number.isInteger(product_id) || product_id < 1 || product_id > 20) {
        throw new Error('商品編號必須是 1 到 20 的整數。');
      }
      this.pending = {request_id: this.new_id(), product_id, expected_run_id: this.run_id};
      this.save();
    }
    return {...this.pending};
  }

  acknowledge(body) {
    if (this.pending && body.ok === true && body.persisted === true &&
        body.order_id === this.pending.request_id) {
      this.pending = null;
      this.save();
      return true;
    }
    return false;
  }

  start_new_run() {
    if (!this.stale) return;
    this.pending = null;
    this.save();
  }
}

function response_message(status, body) {
  if (body.ok && body.persisted) return '訂單已提交。下次按下「下單」會建立新一筆。';
  if (body.ok) return '查詢完成。';
  const reasons = {
    run_changed: '實驗已重設，舊訂單已拒絕。重新檢查狀態後，確認是否開始新實驗的訂單。',
    report_concurrency_budget: '報表名額已滿，請稍後再試。',
    lab_safety_cap: '系統已達工作上限，請稍後再試。',
    queue_timeout: '排隊逾時。訂單若要重試，會沿用同一個鍵。',
    admin_reset: '實驗正在重設，請稍後重新檢查狀態。',
    db_error_or_execution_limit: '資料庫操作未完成或超過期限。訂單將保留原鍵供重試。',
    client_disconnected: '連線已中斷；訂單結果仍需用原鍵確認。',
  };
  return reasons[body.reason] || `請求未確認成功（HTTP ${status}）。訂單將保留原鍵供重試。`;
}

function mount(document, fetch_request, storage, new_id) {
  const intent = new OrderIntent(storage, new_id);
  const element = id => document.getElementById(id);
  let ready = false;
  let ordering = false;

  function show_intent() {
    element('orders').disabled = ordering || !ready || intent.stale;
    element('orders').textContent = intent.pending ? '以原鍵重試訂單' : '下單';
    element('product_id').disabled = ordering || Boolean(intent.pending);
    element('new_run_order').hidden = !intent.stale;
    if (intent.pending) {
      element('product_id').value = intent.pending.product_id;
      element('order_status').textContent = intent.stale
        ? '原實驗已結束，無法在新實驗確認舊訂單。確認開始新實驗後才會清除舊鍵。'
        : `待確認訂單：${intent.pending.request_id} · 商品 ${intent.pending.product_id}。重試會保留相同資料。`;
    } else {
      element('order_status').textContent = '確認成功後才會建立新一筆；請勿將測試訂單混入正式比較。';
    }
    if (!intent.storage_available) {
      element('order_status').textContent += ' 瀏覽器儲存不可用，待確認前請勿重新整理或關閉此頁。';
    }
  }

  async function refresh_status() {
    element('refresh').disabled = true;
    try {
      const response = await fetch_request('/health', {cache: 'no-store', signal: AbortSignal.timeout(3000)});
      const body = await response.json();
      ready = response.ok && body.ready === true && body.lab_id === 'local-resource-defense-lab-v1';
      if (body.lab_id === 'local-resource-defense-lab-v1' && /^[a-f0-9]{16}$/.test(body.run_id)) {
        intent.set_run(body.run_id);
      } else ready = false;
      const gateway = response.headers.get('X-Lab-Gateway-Mode');
      element('status').textContent = `${ready ? '可用' : '尚未就緒'} · 資料庫 ${body.backend || '未知'} · 後端模式 ${body.app_mode || '未知'} · Envoy ${gateway || '未提供（可能直接連線）'} · 實驗 ${body.run_id || '未知'}`;
    } catch (error) {
      ready = false;
      element('status').textContent = `無法確認就緒狀態：${error.message}`;
    } finally {
      element('refresh').disabled = false;
      show_intent();
    }
  }

  element('refresh').onclick = refresh_status;
  element('new_run_order').onclick = () => { intent.start_new_run(); show_intent(); };
  for (const kind of ['products', 'orders', 'report']) {
    element(kind).onclick = async () => {
      const button = element(kind), out = element(`${kind}_result`);
      button.disabled = true;
      out.textContent = '處理中…';
      const start = performance.now();
      try {
        const options = {signal: AbortSignal.timeout(7000)};
        if (kind === 'orders') {
          const payload = intent.payload(Number(element('product_id').value));
          ordering = true;
          show_intent();
          Object.assign(options, {method: 'POST', headers: {'Content-Type': 'application/json'},
                                  body: JSON.stringify(payload)});
        }
        const response = await fetch_request(`/api/${kind}`, options);
        const raw = await response.text();
        let body = {}, formatted = raw;
        try { body = JSON.parse(raw); formatted = JSON.stringify(body, null, 2); } catch {}
        if (kind === 'orders' && response.ok) intent.acknowledge(body);
        if (kind === 'orders' && body.reason === 'run_changed') ready = false;
        out.textContent = `${response_message(response.status, body)}\nHTTP ${response.status} · ${(performance.now()-start).toFixed(1)} ms\n${formatted}`;
      } catch (error) {
        out.textContent = `連線未完成：${error.message}` +
          (kind === 'orders' ? '\n訂單結果尚未確認，請以原鍵重試，勿另開新一筆。' : '');
      } finally {
        if (kind === 'orders') ordering = false;
        button.disabled = false;
        show_intent();
      }
    };
  }
  show_intent();
  return refresh_status();
}

if (typeof module !== 'undefined') module.exports = {OrderIntent, mount};
if (typeof document !== 'undefined') {
  let storage;
  try { storage = sessionStorage; } catch { storage = null; }
  mount(document, (...args) => fetch(...args), storage, () => crypto.randomUUID());
}
