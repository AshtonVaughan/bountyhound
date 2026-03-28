/**
 * ProxyEngine Core — API helper, EventSource client, event bus, global state.
 */

const PE = window.PE = {};

// ── Global State ────────────────────────────────────────────────────────────
PE.state = {
  activePanel: 'dashboard',
  flows: [],
  selectedFlowId: null,
  sseConnected: false,
  badges: {},   // panel -> count
  settings: JSON.parse(localStorage.getItem('pe-settings') || '{}'),
};

PE.saveSetting = (key, value) => {
  PE.state.settings[key] = value;
  localStorage.setItem('pe-settings', JSON.stringify(PE.state.settings));
};

PE.getSetting = (key, fallback) => PE.state.settings[key] ?? fallback;

// ── Event Bus ───────────────────────────────────────────────────────────────
PE.bus = {
  _listeners: {},
  on(event, fn) {
    (this._listeners[event] ||= []).push(fn);
    return () => this.off(event, fn);
  },
  off(event, fn) {
    const arr = this._listeners[event];
    if (arr) this._listeners[event] = arr.filter(f => f !== fn);
  },
  emit(event, data) {
    (this._listeners[event] || []).forEach(fn => {
      try { fn(data); } catch (e) { console.error(`[bus:${event}]`, e); }
    });
  },
};

// ── API Helper ──────────────────────────────────────────────────────────────
const API_BASE = '';

PE.api = {
  async get(path, params) {
    const url = new URL(API_BASE + path, location.origin);
    if (params) Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    });
    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`GET ${path}: ${res.status}`);
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(API_BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`POST ${path}: ${res.status} ${text}`);
    }
    return res.json();
  },

  async put(path, body) {
    const res = await fetch(API_BASE + path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`PUT ${path}: ${res.status}`);
    return res.json();
  },

  async patch(path, body) {
    const res = await fetch(API_BASE + path, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`PATCH ${path}: ${res.status}`);
    return res.json();
  },

  async del(path) {
    const res = await fetch(API_BASE + path, { method: 'DELETE' });
    if (!res.ok) throw new Error(`DELETE ${path}: ${res.status}`);
    return res.json();
  },

  async getText(path) {
    const res = await fetch(API_BASE + path);
    if (!res.ok) throw new Error(`GET ${path}: ${res.status}`);
    return res.text();
  },
};

// ── SSE Client ──────────────────────────────────────────────────────────────
PE.sse = {
  _source: null,
  _retryTimer: null,

  connect() {
    if (this._source) return;
    try {
      this._source = new EventSource('/api/events');
      this._source.onopen = () => {
        PE.state.sseConnected = true;
        PE.bus.emit('sse:connected');
      };
      this._source.addEventListener('flow', (e) => {
        try {
          const data = JSON.parse(e.data);
          PE.bus.emit('flow:new', data);
        } catch (_) {}
      });
      this._source.addEventListener('flow_update', (e) => {
        try { PE.bus.emit('flow:update', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.addEventListener('finding', (e) => {
        try { PE.bus.emit('finding:new', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.addEventListener('scan_progress', (e) => {
        try { PE.bus.emit('scan:progress', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.addEventListener('intruder_progress', (e) => {
        try { PE.bus.emit('intruder:progress', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.addEventListener('intercept', (e) => {
        try { PE.bus.emit('intercept:new', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.addEventListener('collab', (e) => {
        try { PE.bus.emit('collab:interaction', JSON.parse(e.data)); } catch (_) {}
      });
      this._source.onerror = () => {
        PE.state.sseConnected = false;
        PE.bus.emit('sse:disconnected');
        this._source.close();
        this._source = null;
        this._retryTimer = setTimeout(() => this.connect(), 3000);
      };
    } catch (e) {
      // SSE not available, fall back to polling
      this._startPolling();
    }
  },

  _pollTimer: null,
  _startPolling() {
    if (this._pollTimer) return;
    this._pollTimer = setInterval(() => PE.bus.emit('poll:tick'), 2000);
  },

  disconnect() {
    if (this._source) { this._source.close(); this._source = null; }
    clearTimeout(this._retryTimer);
    clearInterval(this._pollTimer);
  },
};

// ── DOM Helpers ─────────────────────────────────────────────────────────────
PE.$ = (sel, root) => (root || document).querySelector(sel);
PE.$$ = (sel, root) => [...(root || document).querySelectorAll(sel)];

PE.el = (tag, attrs, ...children) => {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class' || k === 'className') el.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'html') el.innerHTML = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v);
    }
  }
  for (const child of children) {
    if (child == null) continue;
    if (typeof child === 'string') el.appendChild(document.createTextNode(child));
    else el.appendChild(child);
  }
  return el;
};

// ── Init ────────────────────────────────────────────────────────────────────
PE.init = () => {
  PE.sse.connect();
  PE.bus.emit('app:init');
};
