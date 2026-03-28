/**
 * Crawler Panel — Start crawls, monitor progress, view discovered URLs.
 */
PE.panels = PE.panels || {};

PE.panels.crawler = {
  _container: null,
  _els: {},
  _jobs: [],
  _resultsTable: null,
  _pollTimer: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('crawler-panel');

    // ── Split: config top, results bottom ─────────────────────────────────
    const splitWrap = PE.el('div', { class: 'split-container', style: { display: 'flex', flexDirection: 'column', height: '100%' } });

    const topPane = PE.el('div', { class: 'split-pane' });
    const bottomPane = PE.el('div', { class: 'split-pane' });

    // ── Start Crawl Form ──────────────────────────────────────────────────
    const formSection = PE.el('div', { style: { padding: '12px', borderBottom: '1px solid var(--border)' } });
    formSection.appendChild(PE.el('h3', { text: 'Start Crawl', style: { marginBottom: '8px', fontSize: '14px' } }));

    const formGrid = PE.el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', alignItems: 'end' } });

    // URL input (full width)
    const urlGroup = PE.el('div', { style: { gridColumn: '1 / -1' } });
    urlGroup.appendChild(PE.el('label', { text: 'Target URL', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.urlInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'https://example.com/' });
    urlGroup.appendChild(this._els.urlInput);
    formGrid.appendChild(urlGroup);

    // Max depth
    const depthGroup = PE.el('div');
    depthGroup.appendChild(PE.el('label', { text: 'Max Depth', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.depthInput = PE.el('input', { type: 'number', class: 'input', value: '3', style: { width: '100%' } });
    depthGroup.appendChild(this._els.depthInput);
    formGrid.appendChild(depthGroup);

    // Concurrency
    const concGroup = PE.el('div');
    concGroup.appendChild(PE.el('label', { text: 'Concurrency', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.concurrencyInput = PE.el('input', { type: 'number', class: 'input', value: '5', style: { width: '100%' } });
    concGroup.appendChild(this._els.concurrencyInput);
    formGrid.appendChild(concGroup);

    // JS render toggle
    const jsGroup = PE.el('div', { style: { display: 'flex', alignItems: 'center', gap: '6px' } });
    this._els.jsRenderCb = PE.el('input', { type: 'checkbox', id: 'crawler-js-render' });
    jsGroup.appendChild(this._els.jsRenderCb);
    jsGroup.appendChild(PE.el('label', { text: 'JS Rendering', for: 'crawler-js-render', style: { fontSize: '12px', cursor: 'pointer' } }));
    formGrid.appendChild(jsGroup);

    // Start button
    const startBtn = PE.el('button', { class: 'btn btn-primary', text: 'Start Crawl' });
    startBtn.addEventListener('click', () => this._startCrawl());
    formGrid.appendChild(startBtn);

    formSection.appendChild(formGrid);
    topPane.appendChild(formSection);

    // ── Active Jobs ───────────────────────────────────────────────────────
    const jobsSection = PE.el('div', { style: { padding: '8px 12px' } });
    jobsSection.appendChild(PE.el('h4', { text: 'Active Jobs', style: { marginBottom: '6px', fontSize: '13px' } }));
    this._els.jobsList = PE.el('div', { class: 'crawler-jobs-list' });
    jobsSection.appendChild(this._els.jobsList);
    topPane.appendChild(jobsSection);

    // ── Results Table ─────────────────────────────────────────────────────
    const resultsHeader = PE.el('div', { class: 'panel-section-header', style: { padding: '6px 12px', borderTop: '1px solid var(--border)' } });
    resultsHeader.appendChild(PE.el('h4', { text: 'Discovered URLs', style: { fontSize: '13px' } }));
    this._els.resultCount = PE.el('span', { text: '0 results', style: { marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)' } });
    resultsHeader.appendChild(this._els.resultCount);
    bottomPane.appendChild(resultsHeader);

    this._els.resultsTableWrap = PE.el('div', { class: 'table-wrap', style: { flex: '1' } });
    bottomPane.appendChild(this._els.resultsTableWrap);

    this._resultsTable = new PE.VirtualTable(this._els.resultsTableWrap, {
      columns: [
        { key: 'url', label: 'URL', flex: '2', sortable: true, render: (v) => `<span title="${PE.utils.escapeHtml(v || '')}">${PE.utils.escapeHtml(PE.utils.truncate(v, 80))}</span>` },
        { key: 'method', label: 'Method', width: '70px', sortable: true, render: (v) => `<span class="${PE.utils.methodClass(v)}">${PE.utils.escapeHtml(v || 'GET')}</span>` },
        { key: 'status', label: 'Status', width: '65px', sortable: true, render: (v) => v ? `<span class="${PE.utils.statusClass(v)}">${v}</span>` : '' },
        { key: 'content_type', label: 'Type', width: '120px', sortable: true, render: (v) => PE.utils.escapeHtml(PE.utils.truncate(v, 20)) },
        { key: 'depth', label: 'Depth', width: '55px', sortable: true },
        { key: 'params', label: 'Params', width: '60px', sortable: true, render: (v) => {
          if (!v || (Array.isArray(v) && !v.length)) return '';
          const count = Array.isArray(v) ? v.length : (typeof v === 'number' ? v : 0);
          return count > 0 ? `<span class="badge">${count}</span>` : '';
        }},
      ],
      rowHeight: 28,
      getId: (row) => row.id || row.url,
      onRowClick: (row) => {
        if (row && row.url) PE.utils.copyToClipboard(row.url);
      },
    });

    splitWrap.appendChild(topPane);
    splitWrap.appendChild(PE.el('div', { class: 'split-handle' }));
    splitWrap.appendChild(bottomPane);
    container.appendChild(splitWrap);

    new PE.SplitPane(splitWrap, { direction: 'vertical', initialRatio: 0.35, storageKey: 'crawler-split' });

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'crawler') this._startPolling();
      else this._stopPolling();
    });

    PE.bus.on('crawler:start', (data) => {
      if (data && data.url) {
        this._els.urlInput.value = data.url;
        PE.bus.emit('panel:switch', 'crawler');
      }
    });

    this._loadJobs();
  },

  async _startCrawl() {
    const url = this._els.urlInput.value.trim();
    if (!url) { PE.toast.warning('URL is required'); return; }

    try {
      await PE.api.post('/api/crawler/start', {
        url,
        max_depth: parseInt(this._els.depthInput.value) || 3,
        concurrency: parseInt(this._els.concurrencyInput.value) || 5,
        js_render: this._els.jsRenderCb.checked,
      });
      PE.toast.success('Crawl started');
      this._startPolling();
    } catch (e) {
      PE.toast.error('Failed to start crawl: ' + e.message);
    }
  },

  async _loadJobs() {
    try {
      const data = await PE.api.get('/api/crawler/jobs');
      this._jobs = data.jobs || data || [];
      this._renderJobs();
      this._loadResults();
    } catch (e) {
      console.error('[crawler] Failed to load jobs:', e);
    }
  },

  _renderJobs() {
    this._els.jobsList.innerHTML = '';

    if (!this._jobs.length) {
      this._els.jobsList.appendChild(PE.el('div', { text: 'No active crawl jobs', style: { color: 'var(--text-muted)', fontSize: '12px', padding: '4px 0' } }));
      return;
    }

    this._jobs.forEach((job, idx) => {
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

      // URL
      row.appendChild(PE.el('span', { text: PE.utils.truncate(job.url || '', 40), style: { flex: '1', fontSize: '12px' } }));

      // Progress
      const found = job.urls_found || 0;
      const queued = job.urls_queued || job.urls_total || 0;
      const progressWrap = PE.el('div', { style: { width: '160px' } });
      const progressText = PE.el('div', { text: `${found} found / ${queued} queued`, style: { fontSize: '10px', color: 'var(--text-muted)', marginBottom: '2px' } });
      const progressBar = PE.el('div', { class: 'progress-bar', style: { height: '4px' } });
      const pct = queued > 0 ? Math.round((found / queued) * 100) : 0;
      progressBar.appendChild(PE.el('div', { class: 'progress-bar-fill', style: { width: pct + '%' } }));
      progressWrap.appendChild(progressText);
      progressWrap.appendChild(progressBar);
      row.appendChild(progressWrap);

      // Cancel button
      if (job.status === 'running') {
        const cancelBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Cancel' });
        cancelBtn.addEventListener('click', () => this._cancelCrawl(job.id || idx));
        row.appendChild(cancelBtn);
      }

      // View results button
      const viewBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Results' });
      viewBtn.addEventListener('click', () => this._loadResults(job.id || idx));
      row.appendChild(viewBtn);

      this._els.jobsList.appendChild(row);
    });
  },

  async _cancelCrawl(jobId) {
    try {
      await PE.api.post(`/api/crawler/jobs/${jobId}/cancel`, {});
      PE.toast.success('Crawl cancelled');
      this._loadJobs();
    } catch (e) {
      PE.toast.error('Failed to cancel: ' + e.message);
    }
  },

  async _loadResults(jobId) {
    try {
      const params = jobId !== undefined ? { job_id: jobId } : {};
      const data = await PE.api.get('/api/crawler/results', params);
      const results = data.results || data || [];
      this._resultsTable.setData(results);
      this._els.resultCount.textContent = `${results.length} result${results.length !== 1 ? 's' : ''}`;
    } catch (e) {
      console.error('[crawler] Failed to load results:', e);
    }
  },

  _startPolling() {
    if (this._pollTimer) return;
    this._pollTimer = setInterval(() => this._loadJobs(), 3000);
    this._loadJobs();
  },

  _stopPolling() {
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  },
};
