/**
 * Intruder Panel — Attack config with position markers, payload sets, results table.
 */
PE.panels = PE.panels || {};

PE.panels.intruder = {
  _container: null,
  _table: null,
  _attacking: false,
  _attackId: null,
  _results: [],
  _positionMarker: '\u00a7', // section sign, same as Burp

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('intruder-panel');

    // ── Config section ──────────────────────────────────────────────────────
    const configSection = PE.el('div', { class: 'intruder-config' });

    // Row 1: Target + attack type
    const topRow = PE.el('div', { class: 'intruder-top-row' });

    // Method
    this._methodInput = PE.el('select', { class: 'intruder-method-select' });
    for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
      this._methodInput.appendChild(PE.el('option', { value: m, text: m }));
    }
    topRow.appendChild(this._labelWrap('Method', this._methodInput));

    // URL
    this._urlInput = PE.el('input', {
      type: 'text',
      class: 'intruder-url-input',
      placeholder: 'https://target.com/api/endpoint',
    });
    topRow.appendChild(this._labelWrap('Target URL', this._urlInput));

    // Attack type
    this._attackType = PE.el('select', { class: 'intruder-attack-type' });
    const types = [
      { value: 'sniper', label: 'Sniper' },
      { value: 'battering_ram', label: 'Battering Ram' },
      { value: 'pitchfork', label: 'Pitchfork' },
      { value: 'cluster_bomb', label: 'Cluster Bomb' },
    ];
    for (const t of types) {
      this._attackType.appendChild(PE.el('option', { value: t.value, text: t.label }));
    }
    topRow.appendChild(this._labelWrap('Attack Type', this._attackType));

    configSection.appendChild(topRow);

    // Row 2: Headers editor with position markers
    const headersRow = PE.el('div', { class: 'intruder-headers-row' });
    headersRow.appendChild(PE.el('div', { class: 'intruder-section-label', text: 'Headers (use \u00a7value\u00a7 to mark positions)' }));
    this._headersEditor = PE.el('textarea', {
      class: 'intruder-headers-editor',
      placeholder: 'Content-Type: application/json\nAuthorization: Bearer \u00a7token\u00a7',
      spellcheck: 'false',
      rows: '4',
    });
    headersRow.appendChild(this._headersEditor);
    configSection.appendChild(headersRow);

    // Row 3: Body editor with position markers
    const bodyRow = PE.el('div', { class: 'intruder-body-row' });
    const bodyHeader = PE.el('div', { class: 'intruder-body-header' });
    bodyHeader.appendChild(PE.el('div', { class: 'intruder-section-label', text: 'Body (use \u00a7value\u00a7 to mark positions)' }));

    // Position marker buttons
    const markerBtns = PE.el('div', { class: 'intruder-marker-btns' });
    const addMarkerBtn = PE.el('button', { class: 'btn btn-sm', text: 'Add \u00a7' });
    addMarkerBtn.addEventListener('click', () => this._insertMarker(this._bodyEditor));
    markerBtns.appendChild(addMarkerBtn);

    const clearMarkersBtn = PE.el('button', { class: 'btn btn-sm', text: 'Clear \u00a7' });
    clearMarkersBtn.addEventListener('click', () => this._clearMarkers());
    markerBtns.appendChild(clearMarkersBtn);

    const autoMarkBtn = PE.el('button', { class: 'btn btn-sm', text: 'Auto \u00a7' });
    autoMarkBtn.addEventListener('click', () => this._autoMark());
    markerBtns.appendChild(autoMarkBtn);

    bodyHeader.appendChild(markerBtns);
    bodyRow.appendChild(bodyHeader);

    this._bodyEditor = PE.el('textarea', {
      class: 'intruder-body-editor',
      placeholder: '{"username":"\u00a7admin\u00a7","password":"\u00a7password\u00a7"}',
      spellcheck: 'false',
      rows: '5',
    });
    bodyRow.appendChild(this._bodyEditor);
    configSection.appendChild(bodyRow);

    // Row 4: Payload config
    const payloadRow = PE.el('div', { class: 'intruder-payload-row' });

    // Payload type
    this._payloadType = PE.el('select', { class: 'intruder-payload-type' });
    const payloadTypes = [
      { value: 'simple_list', label: 'Simple List' },
      { value: 'numbers', label: 'Numbers' },
      { value: 'brute_forcer', label: 'Brute Forcer' },
      { value: 'runtime_file', label: 'Runtime File' },
      { value: 'null_payloads', label: 'Null Payloads' },
    ];
    for (const pt of payloadTypes) {
      this._payloadType.appendChild(PE.el('option', { value: pt.value, text: pt.label }));
    }
    payloadRow.appendChild(this._labelWrap('Payload Type', this._payloadType));

    // Payload input
    const payloadInputWrap = PE.el('div', { class: 'intruder-payload-input-wrap' });
    payloadInputWrap.appendChild(PE.el('div', { class: 'intruder-section-label', text: 'Payloads (one per line)' }));
    this._payloadInput = PE.el('textarea', {
      class: 'intruder-payload-input',
      placeholder: 'admin\ntest\nuser\nroot\n123456',
      spellcheck: 'false',
      rows: '5',
    });
    payloadInputWrap.appendChild(this._payloadInput);
    payloadRow.appendChild(payloadInputWrap);

    configSection.appendChild(payloadRow);

    // Row 5: Options (concurrency, delay)
    const optionsRow = PE.el('div', { class: 'intruder-options-row' });

    // Concurrency
    this._concurrency = PE.el('input', {
      type: 'range', min: '1', max: '50', value: '10', class: 'intruder-concurrency',
    });
    this._concurrencyLabel = PE.el('span', { class: 'intruder-concurrency-val', text: '10' });
    this._concurrency.addEventListener('input', () => {
      this._concurrencyLabel.textContent = this._concurrency.value;
    });
    const concWrap = PE.el('div', { class: 'intruder-option-group' });
    concWrap.appendChild(PE.el('label', { text: 'Concurrency: ' }));
    concWrap.appendChild(this._concurrency);
    concWrap.appendChild(this._concurrencyLabel);
    optionsRow.appendChild(concWrap);

    // Delay
    this._delay = PE.el('input', {
      type: 'number', min: '0', max: '10000', value: '0', class: 'intruder-delay',
      placeholder: 'ms',
    });
    const delayWrap = PE.el('div', { class: 'intruder-option-group' });
    delayWrap.appendChild(PE.el('label', { text: 'Delay (ms): ' }));
    delayWrap.appendChild(this._delay);
    optionsRow.appendChild(delayWrap);

    // Start / Stop button
    this._startBtn = PE.el('button', { class: 'btn btn-primary intruder-start-btn', text: 'Start Attack' });
    this._startBtn.addEventListener('click', () => this._toggleAttack());
    optionsRow.appendChild(this._startBtn);

    // Export button
    const exportBtn = PE.el('button', { class: 'btn btn-sm intruder-export-btn', text: 'Export CSV' });
    exportBtn.addEventListener('click', () => this._exportCSV());
    optionsRow.appendChild(exportBtn);

    configSection.appendChild(optionsRow);
    container.appendChild(configSection);

    // ── Progress bar ────────────────────────────────────────────────────────
    this._progressWrap = PE.el('div', { class: 'intruder-progress-wrap', style: { display: 'none' } });
    this._progressBar = PE.el('div', { class: 'progress-bar' });
    this._progressFill = PE.el('div', { class: 'progress-bar-fill' });
    this._progressBar.appendChild(this._progressFill);
    this._progressWrap.appendChild(this._progressBar);
    this._progressLabel = PE.el('span', { class: 'intruder-progress-label', text: '0/0' });
    this._progressWrap.appendChild(this._progressLabel);
    this._progressChart = PE.el('div', { class: 'intruder-progress-chart' });
    this._progressWrap.appendChild(this._progressChart);
    container.appendChild(this._progressWrap);

    // ── Results VirtualTable ────────────────────────────────────────────────
    const resultsSection = PE.el('div', { class: 'intruder-results' });
    resultsSection.appendChild(PE.el('div', { class: 'pane-header', text: 'Results' }));

    const resultsTable = PE.el('div', { class: 'intruder-results-table' });
    resultsSection.appendChild(resultsTable);
    container.appendChild(resultsSection);

    this._table = new PE.VirtualTable(resultsTable, {
      columns: [
        { key: 'index', label: '#', width: '50px', sortable: true },
        { key: 'payload', label: 'Payload', flex: '2', sortable: true,
          render: (v) => `<span class="intruder-payload-cell">${PE.utils.escapeHtml(v || '')}</span>` },
        { key: 'status_code', label: 'Status', width: '70px', sortable: true,
          render: (v) => v ? `<span class="${PE.utils.statusClass(v)}">${v}</span>` : '--' },
        { key: 'content_length', label: 'Length', width: '80px', sortable: true,
          render: (v) => PE.utils.formatBytes(v) },
        { key: 'duration', label: 'Duration', width: '80px', sortable: true,
          render: (v) => v != null ? PE.utils.formatDuration(v) : '' },
      ],
      rowHeight: 28,
      getId: (row) => row.id || String(row.index),
      onRowClick: (row) => this._showResultDetail(row),
    });

    // ── Timing data for chart ───────────────────────────────────────────────
    this._timingData = [];

    // ── SSE listeners ───────────────────────────────────────────────────────
    PE.bus.on('intruder:progress', (data) => this._onProgress(data));
  },

  _labelWrap(label, input) {
    const wrap = PE.el('div', { class: 'intruder-label-wrap' });
    wrap.appendChild(PE.el('label', { class: 'intruder-label', text: label }));
    wrap.appendChild(input);
    return wrap;
  },

  configureFromFlow(flow) {
    if (!flow) return;

    const req = flow.request || {};
    const url = req.url || flow.url || '';

    this._methodInput.value = (req.method || flow.method || 'GET').toUpperCase();
    this._urlInput.value = url;

    // Build headers
    const headerLines = [];
    const headers = req.headers || {};
    for (const [k, v] of Object.entries(headers)) {
      headerLines.push(`${k}: ${v}`);
    }
    this._headersEditor.value = headerLines.join('\n');

    // Body
    this._bodyEditor.value = req.body || '';
  },

  _insertMarker(textarea) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = textarea.value;
    const m = this._positionMarker;

    if (start !== end) {
      // Wrap selection with markers
      textarea.value = text.substring(0, start) + m + text.substring(start, end) + m + text.substring(end);
    } else {
      // Insert paired markers at cursor
      textarea.value = text.substring(0, start) + m + m + text.substring(start);
      textarea.selectionStart = textarea.selectionEnd = start + 1;
    }
    textarea.focus();
  },

  _clearMarkers() {
    const m = this._positionMarker;
    this._headersEditor.value = this._headersEditor.value.replaceAll(m, '');
    this._bodyEditor.value = this._bodyEditor.value.replaceAll(m, '');
    this._urlInput.value = this._urlInput.value.replaceAll(m, '');
  },

  _autoMark() {
    // Auto-detect values in JSON body and mark them
    const body = this._bodyEditor.value;
    if (!body.trim()) return;

    const m = this._positionMarker;
    try {
      // Try JSON: mark all string values
      const obj = JSON.parse(body);
      let marked = body;
      const stringValues = [];
      JSON.stringify(obj, (key, val) => {
        if (typeof val === 'string' && val.length > 0 && key) {
          stringValues.push(val);
        }
        return val;
      });
      // Sort by length descending to avoid partial matches
      stringValues.sort((a, b) => b.length - a.length);
      for (const val of stringValues) {
        // Only mark inside quoted values in JSON
        marked = marked.replace(`"${val}"`, `"${m}${val}${m}"`);
      }
      this._bodyEditor.value = marked;
    } catch (_) {
      // Try URL-encoded: mark all values
      if (body.includes('=')) {
        const marked = body.replace(/=([^&]*)/g, (match, val) => `=${m}${val}${m}`);
        this._bodyEditor.value = marked;
      }
    }
  },

  async _toggleAttack() {
    if (this._attacking) {
      this._stopAttack();
      return;
    }
    this._startAttack();
  },

  async _startAttack() {
    const url = this._urlInput.value.trim();
    if (!url) {
      PE.toast.warning('Enter a target URL');
      return;
    }

    const payloadsRaw = this._payloadInput.value.trim();
    if (!payloadsRaw && this._payloadType.value === 'simple_list') {
      PE.toast.warning('Enter at least one payload');
      return;
    }

    const payloads = payloadsRaw.split('\n').map(p => p.trim()).filter(Boolean);

    // Build headers object
    const headers = {};
    for (const line of this._headersEditor.value.split('\n')) {
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) headers[match[1].trim()] = match[2].trim();
    }

    const config = {
      method: this._methodInput.value,
      url: url,
      headers: headers,
      body: this._bodyEditor.value || null,
      attack_type: this._attackType.value,
      payload_type: this._payloadType.value,
      payloads: payloads,
      concurrency: parseInt(this._concurrency.value) || 10,
      delay: parseInt(this._delay.value) || 0,
    };

    this._attacking = true;
    this._results = [];
    this._timingData = [];
    this._table.clear();
    this._startBtn.textContent = 'Stop Attack';
    this._startBtn.classList.remove('btn-primary');
    this._startBtn.classList.add('btn-danger');
    this._progressWrap.style.display = '';
    this._progressFill.style.width = '0%';
    this._progressLabel.textContent = `0/${payloads.length}`;

    try {
      const result = await PE.api.post('/api/intruder/attack', config);
      this._attackId = result.attack_id || result.id;
    } catch (e) {
      PE.toast.error('Failed to start attack: ' + e.message);
      this._resetAttackUI();
    }
  },

  async _stopAttack() {
    if (!this._attackId) return;
    try {
      await PE.api.post(`/api/intruder/attack/${this._attackId}/stop`);
    } catch (e) {
      PE.toast.error('Failed to stop attack: ' + e.message);
    }
    this._resetAttackUI();
  },

  _resetAttackUI() {
    this._attacking = false;
    this._attackId = null;
    this._startBtn.textContent = 'Start Attack';
    this._startBtn.classList.add('btn-primary');
    this._startBtn.classList.remove('btn-danger');
  },

  _onProgress(data) {
    if (data.attack_id && data.attack_id !== this._attackId) return;

    // Single result
    if (data.result) {
      const r = data.result;
      r.index = this._results.length + 1;
      r.id = r.id || PE.utils.genId();
      this._results.push(r);
      this._table.appendRow(r);
      this._timingData.push(r.duration || 0);
    }

    // Progress update
    if (data.completed != null && data.total != null) {
      const pct = data.total > 0 ? Math.round((data.completed / data.total) * 100) : 0;
      this._progressFill.style.width = pct + '%';
      this._progressLabel.textContent = `${data.completed}/${data.total} (${pct}%)`;

      // Render timing sparkline
      if (this._timingData.length > 1) {
        PE.chart.sparkline(this._progressChart, this._timingData.slice(-100), {
          width: 200,
          height: 30,
          color: 'var(--accent)',
        });
      }
    }

    // Attack complete
    if (data.status === 'completed' || data.status === 'stopped') {
      this._resetAttackUI();
      PE.toast.success(`Attack finished: ${this._results.length} results`);
    }
  },

  _showResultDetail(row) {
    if (!row) return;
    const body = PE.el('div', { class: 'intruder-result-detail' });

    body.appendChild(PE.el('div', { class: 'detail-row' },
      PE.el('strong', { text: 'Payload: ' }),
      PE.el('span', { text: row.payload || '' }),
    ));
    body.appendChild(PE.el('div', { class: 'detail-row' },
      PE.el('strong', { text: 'Status: ' }),
      PE.el('span', { class: PE.utils.statusClass(row.status_code), text: String(row.status_code || '') }),
    ));
    body.appendChild(PE.el('div', { class: 'detail-row' },
      PE.el('strong', { text: 'Length: ' }),
      PE.el('span', { text: PE.utils.formatBytes(row.content_length) }),
    ));
    body.appendChild(PE.el('div', { class: 'detail-row' },
      PE.el('strong', { text: 'Duration: ' }),
      PE.el('span', { text: PE.utils.formatDuration(row.duration) }),
    ));

    if (row.response_body) {
      const respWrap = PE.el('div', { class: 'intruder-result-response' });
      const type = PE.syntax.autoDetect(row.response_body);
      PE.syntax.renderInto(respWrap, row.response_body, type);
      body.appendChild(respWrap);
    }

    PE.modal.show({
      title: `Result #${row.index}`,
      body: body,
      width: '600px',
    });
  },

  _exportCSV() {
    if (!this._results.length) {
      PE.toast.warning('No results to export');
      return;
    }

    const header = ['#', 'Payload', 'Status', 'Length', 'Duration (ms)'];
    const rows = this._results.map(r => [
      r.index,
      `"${(r.payload || '').replace(/"/g, '""')}"`,
      r.status_code || '',
      r.content_length || 0,
      r.duration != null ? Math.round(r.duration) : '',
    ]);

    const csv = [header.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intruder-results-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    PE.toast.success('CSV exported');
  },
};
