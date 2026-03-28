/**
 * Discovery Panel — Directory busting with wordlists and results table.
 */
PE.panels = PE.panels || {};

PE.panels.discovery = {
  _container: null,
  _els: {},
  _jobs: [],
  _resultsTable: null,
  _pollTimer: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('discovery-panel');

    // ── Split: config top, results bottom ─────────────────────────────────
    const splitWrap = PE.el('div', { class: 'split-container', style: { display: 'flex', flexDirection: 'column', height: '100%' } });

    const topPane = PE.el('div', { class: 'split-pane' });
    const bottomPane = PE.el('div', { class: 'split-pane' });

    // ── Start Form ────────────────────────────────────────────────────────
    const formSection = PE.el('div', { style: { padding: '12px', borderBottom: '1px solid var(--border)' } });
    formSection.appendChild(PE.el('h3', { text: 'Directory Discovery', style: { marginBottom: '8px', fontSize: '14px' } }));

    const formGrid = PE.el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', alignItems: 'end' } });

    // Base URL
    const urlGroup = PE.el('div', { style: { gridColumn: '1 / -1' } });
    urlGroup.appendChild(PE.el('label', { text: 'Base URL', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.urlInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'https://example.com/' });
    urlGroup.appendChild(this._els.urlInput);
    formGrid.appendChild(urlGroup);

    // Wordlist selector
    const wlGroup = PE.el('div');
    wlGroup.appendChild(PE.el('label', { text: 'Wordlist', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.wordlistSelect = PE.el('select', { class: 'input', style: { width: '100%' } });
    this._els.wordlistSelect.appendChild(PE.el('option', { value: '', text: 'Loading...' }));
    wlGroup.appendChild(this._els.wordlistSelect);
    formGrid.appendChild(wlGroup);

    // Extensions
    const extGroup = PE.el('div');
    extGroup.appendChild(PE.el('label', { text: 'Extensions', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.extensionsInput = PE.el('input', { type: 'text', class: 'input', placeholder: '.php,.html,.js,.txt', value: '.php,.html,.js,.txt', style: { width: '100%' } });
    extGroup.appendChild(this._els.extensionsInput);
    formGrid.appendChild(extGroup);

    // Concurrency
    const concGroup = PE.el('div');
    concGroup.appendChild(PE.el('label', { text: 'Concurrency', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.concurrencyInput = PE.el('input', { type: 'number', class: 'input', value: '10', style: { width: '100%' } });
    concGroup.appendChild(this._els.concurrencyInput);
    formGrid.appendChild(concGroup);

    // Method selector
    const methodGroup = PE.el('div');
    methodGroup.appendChild(PE.el('label', { text: 'Method', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.methodSelect = PE.el('select', { class: 'input', style: { width: '100%' } });
    this._els.methodSelect.appendChild(PE.el('option', { value: 'GET', text: 'GET' }));
    this._els.methodSelect.appendChild(PE.el('option', { value: 'HEAD', text: 'HEAD' }));
    methodGroup.appendChild(this._els.methodSelect);
    formGrid.appendChild(methodGroup);

    // Recursive toggle + start button row
    const optionsRow = PE.el('div', { style: { gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: '16px' } });

    const recursiveLabel = PE.el('label', { style: { display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer' } });
    this._els.recursiveCb = PE.el('input', { type: 'checkbox' });
    recursiveLabel.appendChild(this._els.recursiveCb);
    recursiveLabel.appendChild(PE.el('span', { text: 'Recursive' }));
    optionsRow.appendChild(recursiveLabel);

    const startBtn = PE.el('button', { class: 'btn btn-primary', text: 'Start Discovery', style: { marginLeft: 'auto' } });
    startBtn.addEventListener('click', () => this._startDiscovery());
    optionsRow.appendChild(startBtn);

    formGrid.appendChild(optionsRow);
    formSection.appendChild(formGrid);
    topPane.appendChild(formSection);

    // ── Active Jobs ───────────────────────────────────────────────────────
    this._els.jobsSection = PE.el('div', { style: { padding: '8px 12px' } });
    this._els.jobsSection.appendChild(PE.el('h4', { text: 'Active Jobs', style: { marginBottom: '6px', fontSize: '13px' } }));
    this._els.jobsList = PE.el('div', { class: 'discovery-jobs-list' });
    this._els.jobsSection.appendChild(this._els.jobsList);
    topPane.appendChild(this._els.jobsSection);

    // ── Results Table ─────────────────────────────────────────────────────
    const resultsHeader = PE.el('div', {
      class: 'panel-section-header',
      style: { display: 'flex', alignItems: 'center', padding: '6px 12px', borderTop: '1px solid var(--border)' },
    });
    resultsHeader.appendChild(PE.el('h4', { text: 'Results', style: { fontSize: '13px' } }));
    this._els.resultCount = PE.el('span', { text: '0 results', style: { marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)' } });
    resultsHeader.appendChild(this._els.resultCount);
    bottomPane.appendChild(resultsHeader);

    this._els.resultsTableWrap = PE.el('div', { class: 'table-wrap', style: { flex: '1' } });
    bottomPane.appendChild(this._els.resultsTableWrap);

    this._resultsTable = new PE.VirtualTable(this._els.resultsTableWrap, {
      columns: [
        { key: 'url', label: 'URL', flex: '2', sortable: true, render: (v) => `<span title="${PE.utils.escapeHtml(v || '')}">${PE.utils.escapeHtml(PE.utils.truncate(v, 70))}</span>` },
        { key: 'status', label: 'Status', width: '70px', sortable: true, render: (v) => {
          if (!v) return '';
          return `<span class="${PE.utils.statusClass(v)} discovery-status-${this._statusCategory(v)}">${v}</span>`;
        }},
        { key: 'length', label: 'Length', width: '80px', sortable: true, render: (v) => v != null ? PE.utils.formatBytes(v) : '' },
        { key: 'content_type', label: 'Content Type', width: '140px', sortable: true, render: (v) => PE.utils.escapeHtml(PE.utils.truncate(v, 24)) },
        { key: 'redirect', label: 'Redirect', flex: '1', sortable: true, render: (v) => v ? `<span title="${PE.utils.escapeHtml(v)}">${PE.utils.escapeHtml(PE.utils.truncate(v, 50))}</span>` : '' },
      ],
      rowHeight: 28,
      getId: (row) => row.id || row.url,
      onRowClick: (row) => {
        if (row && row.url) PE.utils.copyToClipboard(row.url);
      },
      onRowContext: (row, e) => {
        if (!row) return;
        PE.contextMenu.show(e.clientX, e.clientY, [
          { label: 'Copy URL', action: () => PE.utils.copyToClipboard(row.url) },
          { label: 'Open in Browser', action: () => window.open(row.url, '_blank') },
          'separator',
          { label: 'Send to Repeater', action: () => PE.bus.emit('flow:sendToRepeater', { url: row.url, method: 'GET' }) },
          { label: 'Start Crawl Here', action: () => PE.bus.emit('crawler:start', { url: row.url }) },
        ]);
      },
    });

    splitWrap.appendChild(topPane);
    splitWrap.appendChild(PE.el('div', { class: 'split-handle' }));
    splitWrap.appendChild(bottomPane);
    container.appendChild(splitWrap);

    new PE.SplitPane(splitWrap, { direction: 'vertical', initialRatio: 0.38, storageKey: 'discovery-split' });

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'discovery') this._startPolling();
      else this._stopPolling();
    });

    PE.bus.on('discovery:start', (data) => {
      if (data && data.url) {
        this._els.urlInput.value = data.url;
        PE.bus.emit('panel:switch', 'discovery');
      }
    });

    this._loadWordlists();
    this._loadJobs();
  },

  _statusCategory(code) {
    if (code < 300) return 'success';
    if (code < 400) return 'redirect';
    if (code < 500) return 'client-error';
    return 'server-error';
  },

  async _loadWordlists() {
    try {
      const data = await PE.api.get('/api/discovery/wordlists');
      const lists = data.wordlists || data || [];
      this._els.wordlistSelect.innerHTML = '';
      if (!lists.length) {
        this._els.wordlistSelect.appendChild(PE.el('option', { value: '', text: 'No wordlists available' }));
        return;
      }
      lists.forEach(wl => {
        const name = typeof wl === 'string' ? wl : (wl.name || wl.filename);
        const size = wl.size ? ` (${PE.utils.formatBytes(wl.size)})` : '';
        const count = wl.line_count ? ` [${wl.line_count} lines]` : '';
        this._els.wordlistSelect.appendChild(PE.el('option', { value: name, text: name + count + size }));
      });
    } catch (e) {
      this._els.wordlistSelect.innerHTML = '';
      this._els.wordlistSelect.appendChild(PE.el('option', { value: '', text: 'Failed to load wordlists' }));
    }
  },

  async _startDiscovery() {
    const url = this._els.urlInput.value.trim();
    if (!url) { PE.toast.warning('Base URL is required'); return; }

    const wordlist = this._els.wordlistSelect.value;
    if (!wordlist) { PE.toast.warning('Select a wordlist'); return; }

    const extensions = this._els.extensionsInput.value
      .split(',')
      .map(e => e.trim())
      .filter(Boolean);

    try {
      await PE.api.post('/api/discovery/start', {
        url,
        wordlist,
        extensions,
        concurrency: parseInt(this._els.concurrencyInput.value) || 10,
        method: this._els.methodSelect.value,
        recursive: this._els.recursiveCb.checked,
      });
      PE.toast.success('Discovery scan started');
      this._startPolling();
    } catch (e) {
      PE.toast.error('Failed to start discovery: ' + e.message);
    }
  },

  async _loadJobs() {
    try {
      const data = await PE.api.get('/api/discovery/jobs');
      this._jobs = data.jobs || data || [];
      this._renderJobs();
      this._loadResults();
    } catch (e) {
      console.error('[discovery] Failed to load jobs:', e);
    }
  },

  _renderJobs() {
    this._els.jobsList.innerHTML = '';

    if (!this._jobs.length) {
      this._els.jobsList.appendChild(PE.el('div', { text: 'No active discovery jobs', style: { color: 'var(--text-muted)', fontSize: '12px', padding: '4px 0' } }));
      return;
    }

    this._jobs.forEach((job) => {
      const row = PE.el('div', {
        style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 0', borderBottom: '1px solid var(--border)' },
      });

      // Status indicator
      const statusDot = PE.el('span', {
        style: {
          width: '8px', height: '8px', borderRadius: '50%', flexShrink: '0',
          background: job.status === 'running' ? 'var(--success, #2a9d8f)' : job.status === 'completed' ? 'var(--text-muted)' : 'var(--warning, #fcbf49)',
        },
      });
      row.appendChild(statusDot);

      // URL + wordlist
      const info = PE.el('div', { style: { flex: '1', minWidth: '0' } });
      info.appendChild(PE.el('div', { text: PE.utils.truncate(job.url || '', 50), style: { fontSize: '12px' } }));
      info.appendChild(PE.el('div', { text: `Wordlist: ${job.wordlist || '?'}`, style: { fontSize: '10px', color: 'var(--text-muted)' } }));
      row.appendChild(info);

      // Progress
      const completed = job.completed || job.checked || 0;
      const total = job.total || 0;
      const found = job.found || 0;
      const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

      const progressWrap = PE.el('div', { style: { width: '180px' } });
      progressWrap.appendChild(PE.el('div', {
        text: `${completed}/${total} (${found} found)`,
        style: { fontSize: '10px', color: 'var(--text-muted)', marginBottom: '2px' },
      }));
      const progressBar = PE.el('div', { class: 'progress-bar', style: { height: '4px' } });
      progressBar.appendChild(PE.el('div', { class: 'progress-bar-fill', style: { width: pct + '%' } }));
      progressWrap.appendChild(progressBar);
      row.appendChild(progressWrap);

      // Cancel button
      if (job.status === 'running') {
        const cancelBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Cancel' });
        cancelBtn.addEventListener('click', () => this._cancelJob(job.id));
        row.appendChild(cancelBtn);
      }

      this._els.jobsList.appendChild(row);
    });
  },

  async _cancelJob(jobId) {
    try {
      await PE.api.post(`/api/discovery/jobs/${jobId}/cancel`, {});
      PE.toast.success('Discovery job cancelled');
      this._loadJobs();
    } catch (e) {
      PE.toast.error('Failed to cancel: ' + e.message);
    }
  },

  async _loadResults(jobId) {
    try {
      const params = jobId !== undefined ? { job_id: jobId } : {};
      const data = await PE.api.get('/api/discovery/results', params);
      const results = data.results || data || [];
      this._resultsTable.setData(results);
      this._els.resultCount.textContent = `${results.length} result${results.length !== 1 ? 's' : ''}`;
    } catch (e) {
      console.error('[discovery] Failed to load results:', e);
    }
  },

  _startPolling() {
    if (this._pollTimer) return;
    this._pollTimer = setInterval(() => this._loadJobs(), 2000);
    this._loadJobs();
  },

  _stopPolling() {
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  },
};
