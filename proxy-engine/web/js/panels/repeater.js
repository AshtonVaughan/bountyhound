/**
 * Repeater Panel — Raw request editor + syntax-highlighted response + history.
 * Phase 14: Tab management, diff with previous response, auto-update Host header.
 */
PE.panels = PE.panels || {};

PE.panels.repeater = {
  _container: null,
  _history: [],
  _activeHistoryId: null,
  _sending: false,
  _tabs: [],
  _activeTabIndex: 0,

  // ── Tab helpers ───────────────────────────────────────────────────────────

  _createTab() {
    return {
      id: PE.utils.genId(),
      name: 'Untitled',
      requestText: '',
      targetUrl: '',
      targetLabel: 'No target set',
      responseMeta: null,
      responseHtml: '<div class="empty-state"><div class="title">Send a request to see the response</div></div>',
      history: [],
      lastResponseBody: null,
      prevResponseBody: null,
    };
  },

  _saveCurrentTab() {
    const tab = this._tabs[this._activeTabIndex];
    if (!tab) return;
    tab.requestText = this._requestEditor.value;
    tab.targetUrl = this._targetUrl || '';
    tab.targetLabel = this._targetLabel.textContent;
    tab.responseHtml = this._responseBody.innerHTML;
    tab.responseMeta = this._responseMeta.innerHTML;
    tab.responseMetaVisible = this._responseMeta.style.display !== 'none';
  },

  _loadTab(index) {
    const tab = this._tabs[index];
    if (!tab) return;
    this._activeTabIndex = index;
    this._requestEditor.value = tab.requestText;
    this._targetUrl = tab.targetUrl;
    this._targetLabel.textContent = tab.targetLabel;
    this._responseBody.innerHTML = tab.responseHtml;
    if (tab.responseMeta) {
      this._responseMeta.innerHTML = tab.responseMeta;
      this._responseMeta.style.display = tab.responseMetaVisible ? '' : 'none';
    } else {
      this._responseMeta.style.display = 'none';
      this._responseMeta.innerHTML = '';
    }
    this._history = tab.history;
    this._renderHistory();
    this._renderTabBar();
  },

  _switchTab(index) {
    if (index === this._activeTabIndex) return;
    this._saveCurrentTab();
    this._loadTab(index);
  },

  _addTab() {
    this._saveCurrentTab();
    const tab = this._createTab();
    this._tabs.push(tab);
    this._loadTab(this._tabs.length - 1);
  },

  _closeTab(index) {
    if (this._tabs.length <= 1) return;
    this._tabs.splice(index, 1);
    if (this._activeTabIndex >= this._tabs.length) {
      this._activeTabIndex = this._tabs.length - 1;
    } else if (index < this._activeTabIndex) {
      this._activeTabIndex--;
    } else if (index === this._activeTabIndex) {
      this._activeTabIndex = Math.min(index, this._tabs.length - 1);
    }
    this._loadTab(this._activeTabIndex);
  },

  _tabNameFromUrl(url) {
    if (!url) return 'Untitled';
    try {
      return new URL(url).host || 'Untitled';
    } catch (_) {
      return 'Untitled';
    }
  },

  _renderTabBar() {
    if (!this._tabBar) return;
    this._tabBar.innerHTML = '';

    for (let i = 0; i < this._tabs.length; i++) {
      const tab = this._tabs[i];
      const tabEl = PE.el('div', {
        class: 'repeater-tab' + (i === this._activeTabIndex ? ' active' : ''),
        dataset: { index: String(i) },
      });

      const label = PE.el('span', { class: 'repeater-tab-label', text: tab.name || 'Untitled' });
      tabEl.appendChild(label);

      // Close button (only if more than 1 tab)
      if (this._tabs.length > 1) {
        const closeBtn = PE.el('span', { class: 'repeater-tab-close', text: '\u00d7' });
        closeBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this._closeTab(i);
        });
        tabEl.appendChild(closeBtn);
      }

      tabEl.addEventListener('click', () => this._switchTab(i));
      this._tabBar.appendChild(tabEl);
    }

    // "+" button to add new tab
    const addBtn = PE.el('div', { class: 'repeater-tab repeater-tab-add', text: '+' });
    addBtn.addEventListener('click', () => this._addTab());
    this._tabBar.appendChild(addBtn);
  },

  // ── Diff helpers ──────────────────────────────────────────────────────────

  _diffResponses() {
    const tab = this._tabs[this._activeTabIndex];
    if (!tab) return;

    if (!tab.prevResponseBody || !tab.lastResponseBody) {
      PE.toast.warning('Need at least 2 responses to diff');
      return;
    }

    const oldLines = tab.prevResponseBody.split('\n');
    const newLines = tab.lastResponseBody.split('\n');
    const diff = this._computeSimpleDiff(oldLines, newLines);

    let html = '<pre class="repeater-diff">';
    for (const line of diff) {
      const escaped = PE.utils.escapeHtml(line.text);
      if (line.type === 'add') {
        html += `<div class="diff-add">+ ${escaped}</div>`;
      } else if (line.type === 'remove') {
        html += `<div class="diff-remove">- ${escaped}</div>`;
      } else {
        html += `<div class="diff-ctx">  ${escaped}</div>`;
      }
    }
    html += '</pre>';

    this._responseMeta.style.display = '';
    this._responseMeta.innerHTML = '<span class="response-status" style="color:var(--accent)">DIFF</span>';
    this._responseBody.innerHTML = html;
  },

  _computeSimpleDiff(oldLines, newLines) {
    const result = [];
    let oi = 0;
    let ni = 0;
    while (oi < oldLines.length && ni < newLines.length) {
      if (oldLines[oi] === newLines[ni]) {
        result.push({ type: 'ctx', text: oldLines[oi] });
        oi++;
        ni++;
      } else {
        // Look ahead in newLines to find current oldLine
        let foundInNew = -1;
        for (let j = ni + 1; j < Math.min(ni + 10, newLines.length); j++) {
          if (newLines[j] === oldLines[oi]) { foundInNew = j; break; }
        }
        // Look ahead in oldLines to find current newLine
        let foundInOld = -1;
        for (let j = oi + 1; j < Math.min(oi + 10, oldLines.length); j++) {
          if (oldLines[j] === newLines[ni]) { foundInOld = j; break; }
        }

        if (foundInOld >= 0 && (foundInNew < 0 || (foundInOld - oi) <= (foundInNew - ni))) {
          // Remove old lines until we re-sync
          while (oi < foundInOld) {
            result.push({ type: 'remove', text: oldLines[oi++] });
          }
        } else if (foundInNew >= 0) {
          // Add new lines until we re-sync
          while (ni < foundInNew) {
            result.push({ type: 'add', text: newLines[ni++] });
          }
        } else {
          result.push({ type: 'remove', text: oldLines[oi++] });
          result.push({ type: 'add', text: newLines[ni++] });
        }
      }
    }
    while (oi < oldLines.length) {
      result.push({ type: 'remove', text: oldLines[oi++] });
    }
    while (ni < newLines.length) {
      result.push({ type: 'add', text: newLines[ni++] });
    }
    return result;
  },

  // ── Auto-update Host header ───────────────────────────────────────────────

  _autoUpdateHostHeader() {
    const raw = this._requestEditor.value;
    const lines = raw.split('\n');
    if (lines.length < 1) return;

    // Extract URL from request line
    const reqMatch = lines[0].trim().match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s*(HTTP\/[\d.]+)?$/i);
    if (!reqMatch) return;

    const urlPart = reqMatch[2];
    let host = '';

    // Try to extract host from a full URL
    if (/^https?:\/\//i.test(urlPart)) {
      try {
        host = new URL(urlPart).host;
      } catch (_) {
        return;
      }
    } else {
      return; // Relative URL — Host header is already authoritative
    }

    if (!host) return;

    // Find and update existing Host header
    let found = false;
    for (let i = 1; i < lines.length; i++) {
      if (lines[i].trim() === '') break; // End of headers
      const hMatch = lines[i].match(/^(Host):\s*(.*)$/i);
      if (hMatch) {
        if (hMatch[2].trim() !== host) {
          lines[i] = `Host: ${host}`;
          this._requestEditor.value = lines.join('\n');
        }
        found = true;
        break;
      }
    }

    // If no Host header exists, insert one after the request line
    if (!found) {
      lines.splice(1, 0, `Host: ${host}`);
      this._requestEditor.value = lines.join('\n');
    }
  },

  // ── Init ──────────────────────────────────────────────────────────────────

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('repeater-panel');

    // ── Tab bar ─────────────────────────────────────────────────────────────
    this._tabBar = PE.el('div', { class: 'repeater-tabbar' });
    container.appendChild(this._tabBar);

    // Initialize first tab
    this._tabs = [this._createTab()];
    this._activeTabIndex = 0;

    // ── Top toolbar ─────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'repeater-toolbar' });

    // Target URL display
    this._targetLabel = PE.el('span', { class: 'repeater-target', text: 'No target set' });
    toolbar.appendChild(this._targetLabel);

    // Follow redirects checkbox
    const followLabel = PE.el('label', { class: 'repeater-follow-label' });
    this._followRedirects = PE.el('input', { type: 'checkbox' });
    this._followRedirects.checked = PE.getSetting('repeater-follow-redirects', false);
    this._followRedirects.addEventListener('change', () => {
      PE.saveSetting('repeater-follow-redirects', this._followRedirects.checked);
    });
    followLabel.appendChild(this._followRedirects);
    followLabel.appendChild(PE.el('span', { text: ' Follow redirects' }));
    toolbar.appendChild(followLabel);

    // Send button
    this._sendBtn = PE.el('button', { class: 'btn btn-primary repeater-send-btn', text: 'Send' });
    this._sendBtn.addEventListener('click', () => this._send());
    toolbar.appendChild(this._sendBtn);

    // Diff button
    this._diffBtn = PE.el('button', { class: 'btn btn-sm repeater-diff-btn', text: 'Diff' });
    this._diffBtn.addEventListener('click', () => this._diffResponses());
    toolbar.appendChild(this._diffBtn);

    container.appendChild(toolbar);

    // ── Main split: left=editor, right=response ─────────────────────────────
    const mainSplit = PE.el('div', { class: 'repeater-main-split' });

    const leftPane = PE.el('div', { class: 'split-pane repeater-left-pane' });
    const rightPane = PE.el('div', { class: 'split-pane repeater-right-pane' });
    mainSplit.appendChild(leftPane);
    mainSplit.appendChild(rightPane);
    container.appendChild(mainSplit);

    this._mainSplit = new PE.SplitPane(mainSplit, {
      direction: 'horizontal',
      initialRatio: 0.45,
      storageKey: 'repeater-main-split',
      minSize: 200,
    });

    // ── Left pane: Request editor ───────────────────────────────────────────
    leftPane.appendChild(PE.el('div', { class: 'pane-header', text: 'Request' }));

    this._requestEditor = PE.el('textarea', {
      class: 'repeater-request-editor',
      placeholder: 'GET /path HTTP/1.1\nHost: example.com\nUser-Agent: ProxyEngine/1.0\n\n',
      spellcheck: 'false',
    });
    this._requestEditor.addEventListener('keydown', (e) => {
      // Ctrl+Enter to send
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        this._send();
      }
      // Tab inserts spaces
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = this._requestEditor.selectionStart;
        const end = this._requestEditor.selectionEnd;
        this._requestEditor.value = this._requestEditor.value.substring(0, start) + '  ' + this._requestEditor.value.substring(end);
        this._requestEditor.selectionStart = this._requestEditor.selectionEnd = start + 2;
      }
    });
    // Auto-update Host header on blur
    this._requestEditor.addEventListener('blur', () => this._autoUpdateHostHeader());
    leftPane.appendChild(this._requestEditor);

    // ── Right pane: Response ────────────────────────────────────────────────
    rightPane.appendChild(PE.el('div', { class: 'pane-header', text: 'Response' }));

    // Response meta bar
    this._responseMeta = PE.el('div', { class: 'repeater-response-meta', style: { display: 'none' } });
    rightPane.appendChild(this._responseMeta);

    // Response body
    this._responseBody = PE.el('div', { class: 'repeater-response-body' });
    this._responseBody.innerHTML = '<div class="empty-state"><div class="title">Send a request to see the response</div></div>';
    rightPane.appendChild(this._responseBody);

    // ── Bottom: History list ────────────────────────────────────────────────
    const historySection = PE.el('div', { class: 'repeater-history-section' });
    const historyHeader = PE.el('div', { class: 'repeater-history-header' });
    historyHeader.appendChild(PE.el('span', { class: 'pane-header', text: 'History' }));

    const clearHistoryBtn = PE.el('button', { class: 'btn btn-sm', text: 'Clear' });
    clearHistoryBtn.addEventListener('click', () => this._clearHistory());
    historyHeader.appendChild(clearHistoryBtn);
    historySection.appendChild(historyHeader);

    this._historyList = PE.el('div', { class: 'repeater-history-list' });
    historySection.appendChild(this._historyList);
    container.appendChild(historySection);

    // ── Render tab bar + load history ────────────────────────────────────────
    this._renderTabBar();
    this._loadHistory();
  },

  sendRequest(flow) {
    if (!flow) return;

    const raw = PE.syntax.buildHTTPRequest(flow);
    this._requestEditor.value = raw;

    // Set target label
    const url = flow.request?.url || flow.url || '';
    try {
      const u = new URL(url);
      this._targetUrl = url;
      this._targetLabel.textContent = u.host;
    } catch (_) {
      this._targetUrl = url;
      this._targetLabel.textContent = url;
    }

    // Update active tab name from URL
    const tab = this._tabs[this._activeTabIndex];
    if (tab) {
      tab.name = this._tabNameFromUrl(url);
      this._renderTabBar();
    }
  },

  async _send() {
    if (this._sending) return;

    const rawRequest = this._requestEditor.value.trim();
    if (!rawRequest) {
      PE.toast.warning('Enter a request to send');
      return;
    }

    // Auto-update Host header before parsing
    this._autoUpdateHostHeader();

    // Parse the raw request
    const parsed = this._parseRawRequest(this._requestEditor.value.trim());
    if (!parsed) {
      PE.toast.error('Invalid request format. Expected: METHOD /path HTTP/1.1');
      return;
    }

    // Auto-correct Host header if it doesn't match URL
    if (/^https?:\/\//i.test(parsed.url)) {
      try {
        const urlHost = new URL(parsed.url).host;
        const currentHost = parsed.headers['Host'] || parsed.headers['host'] || '';
        if (currentHost && currentHost !== urlHost) {
          parsed.headers['Host'] = urlHost;
        }
      } catch (_) { /* ignore parse errors */ }
    }

    this._sending = true;
    this._sendBtn.textContent = 'Sending...';
    this._sendBtn.disabled = true;
    this._responseBody.innerHTML = '<div class="empty-state"><div class="title">Sending request...</div></div>';

    const startTime = performance.now();

    try {
      const result = await PE.api.post('/api/repeater/send', {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: parsed.body || null,
        follow_redirects: this._followRedirects.checked,
      });

      const elapsed = performance.now() - startTime;

      // Store response body for diff (shift previous)
      const tab = this._tabs[this._activeTabIndex];
      if (tab) {
        const resp = result.response || result;
        const body = resp.body || '';
        tab.prevResponseBody = tab.lastResponseBody;
        tab.lastResponseBody = body;
        // Update tab name from URL
        tab.name = this._tabNameFromUrl(parsed.url);
        this._renderTabBar();
      }

      this._renderResponse(result, elapsed);
      this._addToHistory(parsed, result, elapsed);
    } catch (e) {
      this._responseMeta.style.display = 'none';
      this._responseBody.innerHTML = `<div class="empty-state error"><div class="title">Request failed</div><div class="subtitle">${PE.utils.escapeHtml(e.message)}</div></div>`;
    } finally {
      this._sending = false;
      this._sendBtn.textContent = 'Send';
      this._sendBtn.disabled = false;
    }
  },

  _parseRawRequest(raw) {
    const lines = raw.split('\n');
    if (!lines.length) return null;

    // Parse request line
    const reqLine = lines[0].trim();
    const reqMatch = reqLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s*(HTTP\/[\d.]+)?$/i);
    if (!reqMatch) return null;

    const method = reqMatch[1].toUpperCase();
    let urlPart = reqMatch[2];

    // Parse headers
    const headers = {};
    let bodyStart = -1;
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim() === '') {
        bodyStart = i + 1;
        break;
      }
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) {
        headers[match[1].trim()] = match[2].trim();
      }
    }

    // Build full URL if relative
    const host = headers['Host'] || headers['host'] || '';
    if (urlPart.startsWith('/') && host) {
      const scheme = this._targetUrl?.startsWith('https') ? 'https' : 'http';
      urlPart = `${scheme}://${host}${urlPart}`;
    }

    // Extract body
    let body = '';
    if (bodyStart > 0 && bodyStart < lines.length) {
      body = lines.slice(bodyStart).join('\n');
    }

    return { method, url: urlPart, headers, body };
  },

  _renderResponse(result, elapsed) {
    const resp = result.response || result;
    const statusCode = resp.status_code || resp.status || 0;
    const headers = resp.headers || {};
    const body = resp.body || '';
    const contentLength = body.length || resp.content_length || 0;
    const duration = resp.duration || elapsed;

    // Meta bar
    const statusClass = PE.utils.statusClass(statusCode);
    this._responseMeta.style.display = '';
    this._responseMeta.innerHTML =
      `<span class="${statusClass} response-status">${statusCode}</span>` +
      `<span class="response-meta-sep">|</span>` +
      `<span class="response-time">${PE.utils.formatDuration(duration)}</span>` +
      `<span class="response-meta-sep">|</span>` +
      `<span class="response-size">${PE.utils.formatBytes(contentLength)}</span>`;

    // Body with syntax highlighting
    const ct = headers['content-type'] || headers['Content-Type'] || '';
    const type = PE.utils.parseContentType(ct);

    if (PE.hexViewer.shouldUseHex(body)) {
      PE.hexViewer.render(this._responseBody, body);
    } else if (type === 'json') {
      PE.syntax.renderInto(this._responseBody, body, 'json');
    } else if (type === 'html' || type === 'xml') {
      PE.syntax.renderInto(this._responseBody, body, 'html');
    } else {
      // Build full HTTP response text
      let raw = `HTTP/1.1 ${statusCode}\n`;
      for (const [k, v] of Object.entries(headers)) {
        raw += `${k}: ${v}\n`;
      }
      raw += `\n${body}`;
      PE.syntax.renderInto(this._responseBody, raw, 'http');
    }
  },

  _addToHistory(request, result, elapsed) {
    const resp = result.response || result;
    const entry = {
      id: PE.utils.genId(),
      timestamp: Date.now() / 1000,
      method: request.method,
      url: request.url,
      status_code: resp.status_code || resp.status || 0,
      duration: resp.duration || elapsed,
      content_length: resp.body?.length || 0,
      rawRequest: this._requestEditor.value,
    };
    this._history.unshift(entry);
    if (this._history.length > 100) this._history.pop();

    // Sync history to active tab
    const tab = this._tabs[this._activeTabIndex];
    if (tab) tab.history = this._history;

    this._renderHistory();
  },

  _renderHistory() {
    this._historyList.innerHTML = '';
    if (!this._history.length) {
      this._historyList.innerHTML = '<div class="empty-state small"><div class="title">No history yet</div></div>';
      return;
    }

    for (const entry of this._history) {
      const item = PE.el('div', {
        class: 'repeater-history-item' + (entry.id === this._activeHistoryId ? ' active' : ''),
        dataset: { id: entry.id },
      });

      const methodSpan = PE.el('span', { class: PE.utils.methodClass(entry.method), text: entry.method });
      const urlSpan = PE.el('span', { class: 'history-url', text: PE.utils.truncate(entry.url, 60) });
      const statusSpan = PE.el('span', { class: PE.utils.statusClass(entry.status_code), text: String(entry.status_code) });
      const timeSpan = PE.el('span', { class: 'history-time', text: PE.utils.formatDuration(entry.duration) });
      const agoSpan = PE.el('span', { class: 'history-ago', text: PE.utils.relativeTime(entry.timestamp) });

      item.appendChild(methodSpan);
      item.appendChild(urlSpan);
      item.appendChild(statusSpan);
      item.appendChild(timeSpan);
      item.appendChild(agoSpan);

      item.addEventListener('click', () => {
        this._activeHistoryId = entry.id;
        this._requestEditor.value = entry.rawRequest || '';
        this._historyList.querySelectorAll('.repeater-history-item').forEach(el => el.classList.remove('active'));
        item.classList.add('active');
      });

      this._historyList.appendChild(item);
    }
  },

  async _loadHistory() {
    try {
      const data = await PE.api.get('/api/repeater/history');
      this._history = (data.history || data || []).map(h => ({
        ...h,
        id: h.id || PE.utils.genId(),
      }));
      // Sync to first tab
      const tab = this._tabs[this._activeTabIndex];
      if (tab) tab.history = this._history;
      this._renderHistory();
    } catch (_) {
      // History endpoint may not exist yet — that is fine
      this._renderHistory();
    }
  },

  _clearHistory() {
    this._history = [];
    this._activeHistoryId = null;
    const tab = this._tabs[this._activeTabIndex];
    if (tab) tab.history = [];
    this._renderHistory();
  },
};
