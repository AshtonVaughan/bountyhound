/**
 * Proxy Panel — Flow table (VirtualTable) + split pane detail view + intercept queue.
 */
PE.panels = PE.panels || {};

PE.panels.proxy = {
  _container: null,
  _table: null,
  _split: null,
  _filter: { text: '', method: '', status: '', scope: false },
  _interceptEnabled: false,
  _interceptQueue: [],
  _allFlows: [],
  _activeDetailTab: 'request',

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('proxy-panel');

    // ── Toolbar ─────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'proxy-toolbar' });

    // Filter input
    const filterInput = PE.el('input', {
      type: 'text',
      class: 'proxy-filter-input',
      placeholder: 'Filter (host, path, regex...)',
    });
    filterInput.addEventListener('input', PE.utils.debounce((e) => {
      this._filter.text = e.target.value;
      this._applyFilters();
    }, 200));
    toolbar.appendChild(filterInput);

    // Method dropdown
    const methodSelect = PE.el('select', { class: 'proxy-method-select' });
    const methods = ['All Methods', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    for (const m of methods) {
      methodSelect.appendChild(PE.el('option', { value: m === 'All Methods' ? '' : m, text: m }));
    }
    methodSelect.addEventListener('change', () => {
      this._filter.method = methodSelect.value;
      this._applyFilters();
    });
    toolbar.appendChild(methodSelect);

    // Status filter
    const statusSelect = PE.el('select', { class: 'proxy-status-select' });
    const statuses = ['All Status', '2xx', '3xx', '4xx', '5xx', 'No Response'];
    for (const s of statuses) {
      statusSelect.appendChild(PE.el('option', { value: s === 'All Status' ? '' : s, text: s }));
    }
    statusSelect.addEventListener('change', () => {
      this._filter.status = statusSelect.value;
      this._applyFilters();
    });
    toolbar.appendChild(statusSelect);

    // Scope toggle
    const scopeBtn = PE.el('button', {
      class: 'btn btn-sm proxy-scope-btn',
      text: 'Scope',
      title: 'Show only in-scope flows',
    });
    scopeBtn.addEventListener('click', () => {
      this._filter.scope = !this._filter.scope;
      scopeBtn.classList.toggle('active', this._filter.scope);
      this._applyFilters();
    });
    toolbar.appendChild(scopeBtn);

    // Intercept toggle
    this._interceptBtn = PE.el('button', {
      class: 'btn btn-sm proxy-intercept-btn',
      text: 'Intercept Off',
    });
    this._interceptBtn.addEventListener('click', () => this._toggleIntercept());
    toolbar.appendChild(this._interceptBtn);

    // Clear button
    const clearBtn = PE.el('button', { class: 'btn btn-sm btn-danger proxy-clear-btn', text: 'Clear' });
    clearBtn.addEventListener('click', () => this._clearFlows());
    toolbar.appendChild(clearBtn);

    // Flow count
    this._flowCountEl = PE.el('span', { class: 'proxy-flow-count', text: '0 flows' });
    toolbar.appendChild(this._flowCountEl);

    container.appendChild(toolbar);

    // ── Intercept banner ────────────────────────────────────────────────────
    this._interceptBanner = PE.el('div', { class: 'proxy-intercept-banner', style: { display: 'none' } });
    this._interceptBanner.appendChild(PE.el('span', { class: 'proxy-intercept-label', text: 'Intercepted request pending' }));
    const forwardBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Forward' });
    forwardBtn.addEventListener('click', () => this._forwardIntercepted());
    this._interceptBanner.appendChild(forwardBtn);
    const dropBtn = PE.el('button', { class: 'btn btn-sm btn-danger', text: 'Drop' });
    dropBtn.addEventListener('click', () => this._dropIntercepted());
    this._interceptBanner.appendChild(dropBtn);
    container.appendChild(this._interceptBanner);

    // ── Split pane: top=table, bottom=detail ────────────────────────────────
    const splitWrap = PE.el('div', { class: 'proxy-split-wrap' });
    const topPane = PE.el('div', { class: 'split-pane proxy-table-pane' });
    const bottomPane = PE.el('div', { class: 'split-pane proxy-detail-pane' });
    splitWrap.appendChild(topPane);
    splitWrap.appendChild(bottomPane);
    container.appendChild(splitWrap);

    this._split = new PE.SplitPane(splitWrap, {
      direction: 'vertical',
      initialRatio: 0.55,
      storageKey: 'proxy-split',
      minSize: 80,
    });

    // ── VirtualTable ────────────────────────────────────────────────────────
    this._table = new PE.VirtualTable(topPane, {
      columns: [
        { key: 'index', label: '#', width: '50px', sortable: true,
          render: (v) => `<span class="flow-idx">${v ?? ''}</span>` },
        { key: 'method', label: 'Method', width: '70px', sortable: true,
          render: (v) => `<span class="${PE.utils.methodClass(v)}">${PE.utils.escapeHtml(v || '')}</span>` },
        { key: 'host', label: 'Host', flex: '1', sortable: true },
        { key: 'path', label: 'Path', flex: '2', sortable: true,
          render: (v) => PE.utils.escapeHtml(PE.utils.truncate(v, 80)) },
        { key: 'status_code', label: 'Status', width: '60px', sortable: true,
          render: (v) => v ? `<span class="${PE.utils.statusClass(v)}">${v}</span>` : '<span class="status-pending">--</span>' },
        { key: 'content_length', label: 'Length', width: '70px', sortable: true,
          render: (v) => PE.utils.formatBytes(v) },
        { key: 'duration', label: 'Time', width: '70px', sortable: true,
          render: (v) => v != null ? PE.utils.formatDuration(v) : '' },
      ],
      rowHeight: 28,
      getId: (row) => row.id,
      onRowClick: (row) => this._showFlowDetail(row),
      onRowDblClick: (row) => {
        if (row) PE.bus.emit('flow:sendToRepeater', row);
      },
      onRowContext: (row, e) => {
        if (row) PE.contextMenu.flowMenu(row, e.clientX, e.clientY);
      },
    });

    // ── Detail pane tabs ────────────────────────────────────────────────────
    this._buildDetailPane(bottomPane);

    // ── Event listeners ─────────────────────────────────────────────────────
    PE.bus.on('flow:new', (flow) => this._onFlowNew(flow));
    PE.bus.on('flow:update', (flow) => this._onFlowUpdate(flow));
    PE.bus.on('flow:updated', (flowId) => this._onFlowRefresh(flowId));
    PE.bus.on('flow:delete', (flow) => this._onFlowDelete(flow));
    PE.bus.on('intercept:new', (data) => this._onIntercept(data));
    PE.bus.on('panel:activated', (id) => {
      if (id === 'proxy') this.refresh();
    });
    PE.bus.on('flow:sendToRepeater', (flow) => {
      PE.panels.repeater?.sendRequest(flow);
      PE.tabManager.switchTo('repeater');
    });
    PE.bus.on('flow:sendToIntruder', (flow) => {
      PE.panels.intruder?.configureFromFlow(flow);
      PE.tabManager.switchTo('intruder');
    });

    // Initial load
    this.refresh();
  },

  _buildDetailPane(container) {
    container.innerHTML = '';

    // Tab bar for detail sub-tabs
    const tabbar = PE.el('div', { class: 'detail-tabbar' });
    const tabs = ['Request', 'Response', 'Headers', 'Hex'];
    for (const name of tabs) {
      const key = name.toLowerCase();
      const tab = PE.el('div', {
        class: 'detail-tab' + (key === 'request' ? ' active' : ''),
        text: name,
        dataset: { tab: key },
      });
      tab.addEventListener('click', () => {
        tabbar.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        this._activeDetailTab = key;
        this._renderDetailContent();
      });
      tabbar.appendChild(tab);
    }
    container.appendChild(tabbar);

    // Detail content area
    this._detailContent = PE.el('div', { class: 'detail-content' });
    this._detailContent.innerHTML = '<div class="empty-state"><div class="title">Select a flow to view details</div></div>';
    container.appendChild(this._detailContent);
  },

  _showFlowDetail(flow) {
    if (!flow) return;
    PE.state.selectedFlowId = flow.id;
    this._selectedFlow = flow;
    this._renderDetailContent();
  },

  async _renderDetailContent() {
    const flow = this._selectedFlow;
    if (!flow) return;

    // Fetch full flow detail if needed
    let detail = flow;
    if (!flow.request || !flow._detailLoaded) {
      try {
        detail = await PE.api.get(`/api/flows/${flow.id}`);
        Object.assign(flow, detail, { _detailLoaded: true });
      } catch (e) {
        this._detailContent.innerHTML = `<div class="empty-state"><div class="title">Failed to load flow details</div></div>`;
        return;
      }
    }

    const tab = this._activeDetailTab;
    const content = this._detailContent;
    content.innerHTML = '';

    switch (tab) {
      case 'request': {
        const raw = PE.syntax.buildHTTPRequest(detail);
        const pre = PE.el('div', { class: 'syntax-wrap' });
        PE.syntax.renderInto(pre, raw, 'http');
        content.appendChild(pre);
        break;
      }
      case 'response': {
        if (!detail.response) {
          content.innerHTML = '<div class="empty-state"><div class="title">No response received</div></div>';
          return;
        }
        const raw = PE.syntax.buildHTTPResponse(detail);
        const ct = detail.response.headers?.['content-type'] || '';
        const bodyType = PE.utils.parseContentType(ct);

        // Response meta bar
        const meta = PE.el('div', { class: 'response-meta' });
        const statusClass = PE.utils.statusClass(detail.response.status_code);
        meta.innerHTML = `<span class="${statusClass}">${detail.response.status_code} ${PE.utils.escapeHtml(detail.response.reason || '')}</span>` +
          `<span class="response-meta-sep">|</span>` +
          `<span>${PE.utils.formatDuration(detail.duration || 0)}</span>` +
          `<span class="response-meta-sep">|</span>` +
          `<span>${PE.utils.formatBytes(detail.response.body?.length || detail.content_length || 0)}</span>`;
        content.appendChild(meta);

        // Body with syntax highlighting based on content type
        const pre = PE.el('div', { class: 'syntax-wrap' });
        if (bodyType === 'json' && detail.response.body) {
          PE.syntax.renderInto(pre, detail.response.body, 'json');
        } else if (bodyType === 'html' && detail.response.body) {
          PE.syntax.renderInto(pre, detail.response.body, 'html');
        } else {
          PE.syntax.renderInto(pre, raw, 'http');
        }
        content.appendChild(pre);
        break;
      }
      case 'headers': {
        const wrap = PE.el('div', { class: 'headers-wrap' });

        // Request headers
        wrap.appendChild(PE.el('div', { class: 'headers-section-title', text: 'Request Headers' }));
        const reqHeaders = detail.request?.headers || {};
        const reqTable = this._buildHeadersTable(reqHeaders);
        wrap.appendChild(reqTable);

        // Response headers
        if (detail.response?.headers) {
          wrap.appendChild(PE.el('div', { class: 'headers-section-title', text: 'Response Headers' }));
          const resTable = this._buildHeadersTable(detail.response.headers);
          wrap.appendChild(resTable);
        }
        content.appendChild(wrap);
        break;
      }
      case 'hex': {
        const body = detail.response?.body || detail.request?.body || '';
        if (!body) {
          content.innerHTML = '<div class="empty-state"><div class="title">No body content</div></div>';
          return;
        }
        PE.hexViewer.render(content, body);
        break;
      }
    }
  },

  _buildHeadersTable(headers) {
    const table = PE.el('table', { class: 'headers-table' });
    for (const [name, value] of Object.entries(headers)) {
      const row = PE.el('tr');
      row.appendChild(PE.el('td', { class: 'header-name', text: name }));
      row.appendChild(PE.el('td', { class: 'header-value', text: value }));
      row.addEventListener('click', () => PE.utils.copyToClipboard(`${name}: ${value}`));
      table.appendChild(row);
    }
    return table;
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/flows', {
        limit: 5000,
        scope: this._filter.scope ? '1' : '',
      });
      const flows = (data.flows || data || []).map((f, i) => this._normalizeFlow(f, i));
      this._allFlows = flows;
      this._applyFilters();
    } catch (e) {
      console.error('[proxy] refresh failed:', e);
    }
  },

  _normalizeFlow(flow, index) {
    let host = flow.host || '';
    let path = flow.path || '';
    if (!host && flow.request?.url) {
      try {
        const u = new URL(flow.request.url);
        host = u.host;
        path = u.pathname + u.search;
      } catch (_) {}
    }
    if (!host && flow.url) {
      try {
        const u = new URL(flow.url);
        host = u.host;
        path = u.pathname + u.search;
      } catch (_) {}
    }
    return {
      ...flow,
      index: flow.index ?? index + 1,
      method: flow.method || flow.request?.method || 'GET',
      host,
      path,
      status_code: flow.status_code || flow.response?.status_code,
      content_length: flow.content_length || flow.response?.body?.length || 0,
      duration: flow.duration,
    };
  },

  _onFlowNew(flow) {
    const idx = this._allFlows.length + 1;
    const normalized = this._normalizeFlow(flow, idx - 1);
    this._allFlows.push(normalized);

    if (this._matchesFilter(normalized)) {
      this._table.appendRow(normalized);
      this._updateFlowCount();
    }
  },

  _onFlowUpdate(update) {
    const existing = this._allFlows.find(f => f.id === update.id);
    if (existing) {
      Object.assign(existing, {
        status_code: update.status_code || update.response?.status_code || existing.status_code,
        content_length: update.content_length || update.response?.body?.length || existing.content_length,
        duration: update.duration ?? existing.duration,
        response: update.response || existing.response,
      });
      this._table.updateRow(update.id, existing);

      if (this._selectedFlow?.id === update.id) {
        Object.assign(this._selectedFlow, existing);
        this._selectedFlow._detailLoaded = false;
        this._renderDetailContent();
      }
    }
  },

  async _onFlowRefresh(flowId) {
    try {
      const detail = await PE.api.get(`/api/flows/${flowId}`);
      const existing = this._allFlows.find(f => f.id === flowId);
      if (existing) {
        Object.assign(existing, detail);
        this._table.updateRow(flowId, existing);
      }
    } catch (_) {}
  },

  _onFlowDelete(flow) {
    this._allFlows = this._allFlows.filter(f => f.id !== flow.id);
    this._applyFilters();
    if (this._selectedFlow?.id === flow.id) {
      this._selectedFlow = null;
      this._detailContent.innerHTML = '<div class="empty-state"><div class="title">Select a flow to view details</div></div>';
    }
  },

  _applyFilters() {
    const filtered = this._allFlows.filter(f => this._matchesFilter(f));
    this._table.setData(filtered);
    this._updateFlowCount();
  },

  _matchesFilter(flow) {
    const f = this._filter;

    if (f.method && flow.method?.toUpperCase() !== f.method.toUpperCase()) return false;

    if (f.status) {
      const code = flow.status_code;
      if (f.status === 'No Response') {
        if (code) return false;
      } else {
        const prefix = f.status.charAt(0);
        if (!code || String(code).charAt(0) !== prefix) return false;
      }
    }

    if (f.text) {
      const needle = f.text.toLowerCase();
      const haystack = `${flow.method} ${flow.host} ${flow.path} ${flow.status_code || ''}`.toLowerCase();
      // Try as regex first, fallback to substring
      try {
        const re = new RegExp(f.text, 'i');
        if (!re.test(haystack)) return false;
      } catch (_) {
        if (!haystack.includes(needle)) return false;
      }
    }

    return true;
  },

  _updateFlowCount() {
    const total = this._table.getTotalCount();
    const all = this._allFlows.length;
    this._flowCountEl.textContent = total === all ? `${total} flows` : `${total}/${all} flows`;
  },

  _toggleIntercept() {
    this._interceptEnabled = !this._interceptEnabled;
    this._interceptBtn.textContent = this._interceptEnabled ? 'Intercept On' : 'Intercept Off';
    this._interceptBtn.classList.toggle('active', this._interceptEnabled);

    PE.api.post('/api/intercept/toggle', { enabled: this._interceptEnabled }).catch(e => {
      PE.toast.error('Failed to toggle intercept: ' + e.message);
      this._interceptEnabled = !this._interceptEnabled;
      this._interceptBtn.textContent = this._interceptEnabled ? 'Intercept On' : 'Intercept Off';
      this._interceptBtn.classList.toggle('active', this._interceptEnabled);
    });
  },

  _onIntercept(data) {
    this._interceptQueue.push(data);
    this._interceptBanner.style.display = '';
    const label = this._interceptBanner.querySelector('.proxy-intercept-label');
    if (label) label.textContent = `${this._interceptQueue.length} intercepted request(s) pending`;
    PE.tabManager.incrementBadge('proxy');
  },

  _forwardIntercepted() {
    if (!this._interceptQueue.length) return;
    const item = this._interceptQueue.shift();
    PE.api.post('/api/intercept/forward', { id: item.id }).catch(e => {
      PE.toast.error('Forward failed: ' + e.message);
    });
    if (!this._interceptQueue.length) {
      this._interceptBanner.style.display = 'none';
    } else {
      const label = this._interceptBanner.querySelector('.proxy-intercept-label');
      if (label) label.textContent = `${this._interceptQueue.length} intercepted request(s) pending`;
    }
  },

  _dropIntercepted() {
    if (!this._interceptQueue.length) return;
    const item = this._interceptQueue.shift();
    PE.api.post('/api/intercept/drop', { id: item.id }).catch(e => {
      PE.toast.error('Drop failed: ' + e.message);
    });
    if (!this._interceptQueue.length) {
      this._interceptBanner.style.display = 'none';
    } else {
      const label = this._interceptBanner.querySelector('.proxy-intercept-label');
      if (label) label.textContent = `${this._interceptQueue.length} intercepted request(s) pending`;
    }
  },

  async _clearFlows() {
    const confirmed = await PE.modal.confirm({
      title: 'Clear Flows',
      message: 'Remove all captured flows? This cannot be undone.',
      confirmLabel: 'Clear All',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await PE.api.del('/api/flows');
      this._allFlows = [];
      this._table.clear();
      this._selectedFlow = null;
      this._detailContent.innerHTML = '<div class="empty-state"><div class="title">Select a flow to view details</div></div>';
      this._updateFlowCount();
      PE.toast.success('Flows cleared');
    } catch (e) {
      PE.toast.error('Failed to clear flows: ' + e.message);
    }
  },

  selectFlow(id) {
    const flow = this._allFlows.find(f => f.id === id);
    if (flow) this._showFlowDetail(flow);
  },
};

// ── Flow Highlighting ────────────────────────────────────────
const HIGHLIGHT_COLORS = ['red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'purple', 'pink'];

function showHighlightMenu(flowId, event) {
    event.preventDefault();
    const menu = document.createElement('div');
    menu.className = 'context-menu highlight-menu';
    menu.style.left = event.pageX + 'px';
    menu.style.top = event.pageY + 'px';

    menu.innerHTML = `
        <div class="context-menu-header">Highlight</div>
        ${HIGHLIGHT_COLORS.map(color => `
            <div class="context-menu-item" onclick="setFlowHighlight('${flowId}', '${color}')">
                <span class="color-dot" style="background:${color}"></span> ${color}
            </div>
        `).join('')}
        <div class="context-menu-item" onclick="setFlowHighlight('${flowId}', '')">
            <span class="color-dot" style="background:#666"></span> None
        </div>
    `;

    document.body.appendChild(menu);
    const closeMenu = () => { menu.remove(); document.removeEventListener('click', closeMenu); };
    setTimeout(() => document.addEventListener('click', closeMenu), 0);
}

async function setFlowHighlight(flowId, color) {
    try {
        await PE.api.patch(`/api/flows/${flowId}`, { highlight: color });
    } catch(e) {
        PE.toast.error('Failed to set highlight');
        return;
    }
    // Re-render the flow row
    const row = document.querySelector(`[data-flow-id="${flowId}"]`);
    if (row) {
        row.style.borderLeft = color ? `3px solid ${color}` : '';
        row.dataset.highlight = color;
        // Apply highlight class
        HIGHLIGHT_COLORS.forEach(c => row.classList.remove(`hl-${c}`));
        if (color) row.classList.add(`hl-${color}`);
    }
}

window.showHighlightMenu = showHighlightMenu;
window.setFlowHighlight = setFlowHighlight;

// ── Editable Intercept ───────────────────────────────────────
function renderInterceptEditor(flow) {
    const container = document.getElementById('intercept-editor');
    if (!container || !flow) return;

    // Build raw HTTP request
    const headers = Object.entries(flow.request?.headers || {})
        .map(([k, v]) => `${k}: ${v}`).join('\r\n');
    const raw = `${flow.request?.method || 'GET'} ${flow.request?.url || '/'} ${flow.request?.http_version || 'HTTP/1.1'}\r\n${headers}\r\n\r\n${flow.request?.body || ''}`;

    container.innerHTML = `
        <div class="intercept-toolbar">
            <button class="btn btn-primary" onclick="forwardInterceptedRequest('${flow.id}')">Forward</button>
            <button class="btn btn-danger" onclick="dropInterceptedRequest('${flow.id}')">Drop</button>
            <button class="btn btn-secondary" onclick="forwardAllIntercepted()">Forward All</button>
        </div>
        <textarea id="intercept-raw-${flow.id}" class="intercept-textarea" spellcheck="false">${PE.utils.escapeHtml(raw)}</textarea>
    `;
}

function parseRawRequest(raw) {
    const lines = raw.split(/\r?\n/);
    if (!lines.length) return null;

    // Parse request line
    const requestLine = lines[0];
    const firstSpace = requestLine.indexOf(' ');
    const lastSpace = requestLine.lastIndexOf(' ');
    const method = requestLine.substring(0, firstSpace);
    const url = requestLine.substring(firstSpace + 1, lastSpace > firstSpace ? lastSpace : undefined);
    const httpVersion = lastSpace > firstSpace ? requestLine.substring(lastSpace + 1) : 'HTTP/1.1';

    // Parse headers
    const headers = {};
    let bodyStart = -1;
    for (let i = 1; i < lines.length; i++) {
        if (lines[i].trim() === '') {
            bodyStart = i + 1;
            break;
        }
        const colonIdx = lines[i].indexOf(':');
        if (colonIdx > 0) {
            headers[lines[i].substring(0, colonIdx).trim()] = lines[i].substring(colonIdx + 1).trim();
        }
    }

    const body = bodyStart >= 0 ? lines.slice(bodyStart).join('\n') : null;
    return { method, url, http_version: httpVersion, headers, body: body || null };
}

async function forwardInterceptedRequest(flowId) {
    const textarea = document.getElementById(`intercept-raw-${flowId}`);
    if (!textarea) return;

    const parsed = parseRawRequest(textarea.value);
    if (!parsed) { PE.toast.error('Failed to parse request'); return; }

    try {
        await PE.api.post(`/api/intercept/${flowId}/resolve`, {
            action: 'forward',
            modifications: parsed
        });
        PE.toast.success('Request forwarded');
    } catch(e) {
        PE.toast.error('Forward failed: ' + e.message);
    }
}

async function dropInterceptedRequest(flowId) {
    try {
        await PE.api.post(`/api/intercept/${flowId}/resolve`, { action: 'drop' });
        PE.toast.success('Request dropped');
    } catch(e) {
        PE.toast.error('Drop failed: ' + e.message);
    }
}

async function forwardAllIntercepted() {
    try {
        const queue = await PE.api.get('/api/intercept/queue');
        if (queue && queue.length) {
            for (const flow of queue) {
                await PE.api.post(`/api/intercept/${flow.id}/resolve`, { action: 'forward' });
            }
            PE.toast.success(`Forwarded ${queue.length} requests`);
        } else {
            PE.toast.info('No intercepted requests in queue');
        }
    } catch(e) {
        PE.toast.error('Forward all failed: ' + e.message);
    }
}

window.renderInterceptEditor = renderInterceptEditor;
window.forwardInterceptedRequest = forwardInterceptedRequest;
window.dropInterceptedRequest = dropInterceptedRequest;
window.forwardAllIntercepted = forwardAllIntercepted;
