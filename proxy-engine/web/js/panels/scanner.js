/**
 * Scanner Panel — Scan management, findings table, severity filters, scan diff.
 */
PE.panels = PE.panels || {};

PE.panels.scanner = {
  _container: null,
  _table: null,
  _scans: [],
  _findings: [],
  _allFindings: [],
  _severityFilter: new Set(['critical', 'high', 'medium', 'low', 'info']),
  _refreshTimer: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('scanner-panel');

    // ── New Scan form ───────────────────────────────────────────────────────
    const newScanSection = PE.el('div', { class: 'scanner-new-scan' });

    const newScanHeader = PE.el('div', { class: 'scanner-section-header' });
    newScanHeader.appendChild(PE.el('div', { class: 'pane-header', text: 'New Scan' }));
    this._toggleFormBtn = PE.el('button', { class: 'btn btn-sm', text: 'Expand' });
    this._toggleFormBtn.addEventListener('click', () => this._toggleForm());
    newScanHeader.appendChild(this._toggleFormBtn);
    newScanSection.appendChild(newScanHeader);

    this._scanForm = PE.el('div', { class: 'scanner-form', style: { display: 'none' } });

    // URL inputs
    const urlGroup = PE.el('div', { class: 'scanner-url-group' });
    urlGroup.appendChild(PE.el('label', { class: 'scanner-label', text: 'Target URLs (one per line)' }));
    this._urlInput = PE.el('textarea', {
      class: 'scanner-url-input',
      placeholder: 'https://example.com\nhttps://example.com/api/v1',
      rows: '3',
      spellcheck: 'false',
    });
    urlGroup.appendChild(this._urlInput);
    this._scanForm.appendChild(urlGroup);

    // Profile + custom checks row
    const configRow = PE.el('div', { class: 'scanner-config-row' });

    // Profile selector
    const profileGroup = PE.el('div', { class: 'scanner-option-group' });
    profileGroup.appendChild(PE.el('label', { class: 'scanner-label', text: 'Scan Profile' }));
    this._profileSelect = PE.el('select', { class: 'scanner-profile-select' });
    const profiles = [
      { value: 'full', label: 'Full Scan' },
      { value: 'quick', label: 'Quick Scan' },
      { value: 'passive', label: 'Passive Only' },
      { value: 'active', label: 'Active Only' },
      { value: 'nuclei', label: 'Nuclei Templates' },
      { value: 'custom', label: 'Custom' },
    ];
    for (const p of profiles) {
      this._profileSelect.appendChild(PE.el('option', { value: p.value, text: p.label }));
    }
    profileGroup.appendChild(this._profileSelect);
    configRow.appendChild(profileGroup);

    // Custom checks
    const checksGroup = PE.el('div', { class: 'scanner-option-group' });
    checksGroup.appendChild(PE.el('label', { class: 'scanner-label', text: 'Custom Checks' }));
    this._checksInput = PE.el('input', {
      type: 'text',
      class: 'scanner-checks-input',
      placeholder: 'sqli,xss,ssti,idor (comma-separated)',
    });
    checksGroup.appendChild(this._checksInput);
    configRow.appendChild(checksGroup);

    this._scanForm.appendChild(configRow);

    // Start scan button
    const formActions = PE.el('div', { class: 'scanner-form-actions' });
    this._startScanBtn = PE.el('button', { class: 'btn btn-primary', text: 'Start Scan' });
    this._startScanBtn.addEventListener('click', () => this._startScan());
    formActions.appendChild(this._startScanBtn);
    this._scanForm.appendChild(formActions);

    newScanSection.appendChild(this._scanForm);
    container.appendChild(newScanSection);

    // ── Active scans list ───────────────────────────────────────────────────
    const scansSection = PE.el('div', { class: 'scanner-scans-section' });
    scansSection.appendChild(PE.el('div', { class: 'pane-header', text: 'Scans' }));
    this._scansList = PE.el('div', { class: 'scanner-scans-list' });
    scansSection.appendChild(this._scansList);
    container.appendChild(scansSection);

    // ── Severity filter buttons ─────────────────────────────────────────────
    const filterBar = PE.el('div', { class: 'scanner-filter-bar' });

    const sevLevels = [
      { key: 'critical', label: 'Critical', color: 'var(--sev-critical, #e63946)' },
      { key: 'high', label: 'High', color: 'var(--sev-high, #f77f00)' },
      { key: 'medium', label: 'Medium', color: 'var(--sev-medium, #fcbf49)' },
      { key: 'low', label: 'Low', color: 'var(--sev-low, #2a9d8f)' },
      { key: 'info', label: 'Info', color: 'var(--sev-info, #457b9d)' },
    ];
    this._filterBtns = {};
    for (const sev of sevLevels) {
      const btn = PE.el('button', {
        class: `btn btn-sm scanner-sev-btn active sev-${sev.key}`,
        text: `${sev.label} (0)`,
        dataset: { severity: sev.key },
      });
      btn.addEventListener('click', () => this._toggleSeverity(sev.key, btn));
      filterBar.appendChild(btn);
      this._filterBtns[sev.key] = btn;
    }

    // Scan comparison dropdown
    const compareWrap = PE.el('div', { class: 'scanner-compare-wrap' });
    compareWrap.appendChild(PE.el('label', { text: 'Compare: ' }));
    this._compareA = PE.el('select', { class: 'scanner-compare-select' });
    this._compareA.appendChild(PE.el('option', { value: '', text: 'Scan A' }));
    compareWrap.appendChild(this._compareA);
    compareWrap.appendChild(PE.el('span', { text: ' vs ' }));
    this._compareB = PE.el('select', { class: 'scanner-compare-select' });
    this._compareB.appendChild(PE.el('option', { value: '', text: 'Scan B' }));
    compareWrap.appendChild(this._compareB);
    const diffBtn = PE.el('button', { class: 'btn btn-sm', text: 'Diff' });
    diffBtn.addEventListener('click', () => this._compareScansDiff());
    compareWrap.appendChild(diffBtn);
    filterBar.appendChild(compareWrap);

    container.appendChild(filterBar);

    // ── Findings VirtualTable ───────────────────────────────────────────────
    const findingsSection = PE.el('div', { class: 'scanner-findings-section' });
    findingsSection.appendChild(PE.el('div', { class: 'pane-header', text: 'Findings' }));

    const tableWrap = PE.el('div', { class: 'scanner-findings-table' });
    findingsSection.appendChild(tableWrap);
    container.appendChild(findingsSection);

    this._table = new PE.VirtualTable(tableWrap, {
      columns: [
        { key: 'severity', label: 'Severity', width: '90px', sortable: true,
          render: (v) => {
            const sev = (v || 'info').toLowerCase();
            return `<span class="badge sev-${sev}">${sev.charAt(0).toUpperCase() + sev.slice(1)}</span>`;
          }},
        { key: 'name', label: 'Name', flex: '2', sortable: true,
          render: (v) => PE.utils.escapeHtml(v || '') },
        { key: 'url', label: 'URL', flex: '2', sortable: true,
          render: (v) => PE.utils.escapeHtml(PE.utils.truncate(v, 70)) },
        { key: 'source', label: 'Source', width: '90px', sortable: true,
          render: (v) => `<span class="scanner-source">${PE.utils.escapeHtml(v || '')}</span>` },
        { key: 'confidence', label: 'Confidence', width: '90px', sortable: true,
          render: (v) => {
            const conf = (v || 'tentative').toLowerCase();
            return `<span class="confidence-${conf}">${conf.charAt(0).toUpperCase() + conf.slice(1)}</span>`;
          }},
      ],
      rowHeight: 32,
      getId: (row) => row.id || PE.utils.genId(),
      onRowClick: (row) => this._showFindingDetail(row),
      onRowContext: (row, e) => this._findingContextMenu(row, e),
    });

    // ── Event listeners ─────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'scanner') this.refresh();
    });
    PE.bus.on('finding:new', (finding) => this._onNewFinding(finding));
    PE.bus.on('scan:progress', (data) => this._onScanProgress(data));
    PE.bus.on('flow:scan', (flow) => this._scanFlow(flow));

    // Initial load
    this.refresh();

    // Periodic refresh for active scans
    this._refreshTimer = setInterval(() => {
      if (PE.state.activePanel === 'scanner') this._refreshScans();
    }, 5000);
  },

  _toggleForm() {
    const visible = this._scanForm.style.display !== 'none';
    this._scanForm.style.display = visible ? 'none' : '';
    this._toggleFormBtn.textContent = visible ? 'Expand' : 'Collapse';
  },

  async refresh() {
    await Promise.all([
      this._refreshScans(),
      this._refreshFindings(),
    ]);
  },

  async _refreshScans() {
    try {
      const data = await PE.api.get('/api/scanner/scans');
      this._scans = data.scans || data || [];
      this._renderScans();
      this._updateCompareDropdowns();
    } catch (e) {
      console.error('[scanner] refresh scans failed:', e);
    }
  },

  async _refreshFindings() {
    try {
      const data = await PE.api.get('/api/scanner/findings');
      this._allFindings = (data.findings || data || []).map(f => ({
        ...f,
        id: f.id || PE.utils.genId(),
      }));
      this._applyFilters();
      this._updateSeverityCounts();
    } catch (e) {
      console.error('[scanner] refresh findings failed:', e);
    }
  },

  _renderScans() {
    this._scansList.innerHTML = '';
    if (!this._scans.length) {
      this._scansList.innerHTML = '<div class="empty-state small"><div class="title">No scans</div></div>';
      return;
    }

    for (const scan of this._scans) {
      const item = PE.el('div', { class: 'scanner-scan-item' });

      const header = PE.el('div', { class: 'scanner-scan-header' });
      const statusIcon = scan.status === 'running' ? '\u25B6' : scan.status === 'completed' ? '\u2714' : scan.status === 'failed' ? '\u2716' : '\u23F8';
      header.appendChild(PE.el('span', { class: `scanner-scan-status status-${scan.status || 'unknown'}`, text: statusIcon }));
      header.appendChild(PE.el('span', { class: 'scanner-scan-name', text: scan.name || scan.profile || 'Scan' }));
      header.appendChild(PE.el('span', { class: 'scanner-scan-target', text: PE.utils.truncate(scan.target || scan.url || '', 40) }));
      header.appendChild(PE.el('span', { class: 'scanner-scan-time', text: PE.utils.relativeTime(scan.started_at || scan.timestamp) }));

      if (scan.status === 'running') {
        const stopBtn = PE.el('button', { class: 'btn btn-sm btn-danger', text: 'Stop' });
        stopBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this._stopScan(scan.id);
        });
        header.appendChild(stopBtn);
      }

      item.appendChild(header);

      // Progress bar for running scans
      if (scan.status === 'running' && scan.total > 0) {
        const pct = Math.round((scan.completed / scan.total) * 100);
        const progBar = PE.el('div', { class: 'progress-bar' });
        progBar.appendChild(PE.el('div', { class: 'progress-bar-fill', style: { width: pct + '%' } }));
        item.appendChild(progBar);
        item.appendChild(PE.el('div', { class: 'scanner-scan-progress-text', text: `${scan.completed}/${scan.total} checks (${pct}%)` }));
      }

      // Finding counts summary
      if (scan.finding_counts) {
        const counts = PE.el('div', { class: 'scanner-scan-counts' });
        for (const [sev, count] of Object.entries(scan.finding_counts)) {
          if (count > 0) {
            counts.appendChild(PE.el('span', { class: `badge sev-${sev.toLowerCase()}`, text: `${count} ${sev}` }));
          }
        }
        item.appendChild(counts);
      }

      this._scansList.appendChild(item);
    }
  },

  _updateCompareDropdowns() {
    const scanOptions = this._scans.filter(s => s.status === 'completed').map(s => ({
      value: s.id,
      label: `${s.name || s.profile || 'Scan'} (${PE.utils.relativeTime(s.started_at || s.timestamp)})`,
    }));

    for (const select of [this._compareA, this._compareB]) {
      const current = select.value;
      select.innerHTML = '';
      select.appendChild(PE.el('option', { value: '', text: '-- Select --' }));
      for (const opt of scanOptions) {
        select.appendChild(PE.el('option', { value: opt.value, text: opt.label }));
      }
      if (current) select.value = current;
    }
  },

  _toggleSeverity(sev, btn) {
    if (this._severityFilter.has(sev)) {
      this._severityFilter.delete(sev);
      btn.classList.remove('active');
    } else {
      this._severityFilter.add(sev);
      btn.classList.add('active');
    }
    this._applyFilters();
  },

  _applyFilters() {
    this._findings = this._allFindings.filter(f => {
      const sev = (f.severity || 'info').toLowerCase();
      return this._severityFilter.has(sev);
    });
    // Sort by severity order
    this._findings.sort((a, b) => PE.utils.sevOrder(a.severity) - PE.utils.sevOrder(b.severity));
    this._table.setData(this._findings);
  },

  _updateSeverityCounts() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this._allFindings) {
      const sev = (f.severity || 'info').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    }
    for (const [sev, btn] of Object.entries(this._filterBtns)) {
      const label = sev.charAt(0).toUpperCase() + sev.slice(1);
      btn.textContent = `${label} (${counts[sev]})`;
    }
  },

  _onNewFinding(finding) {
    finding.id = finding.id || PE.utils.genId();
    this._allFindings.unshift(finding);
    this._applyFilters();
    this._updateSeverityCounts();
    PE.tabManager.incrementBadge('scanner');
  },

  _onScanProgress(data) {
    const scan = this._scans.find(s => s.id === data.id || s.id === data.scan_id);
    if (scan) {
      scan.completed = data.completed ?? scan.completed;
      scan.total = data.total ?? scan.total;
      scan.status = data.status || scan.status;
      if (data.finding_counts) scan.finding_counts = data.finding_counts;
      this._renderScans();
    }

    if (data.status === 'completed') {
      PE.toast.success(`Scan completed: ${data.name || ''}`);
      this._refreshFindings();
    }
  },

  async _startScan() {
    const urls = this._urlInput.value.trim().split('\n').map(u => u.trim()).filter(Boolean);
    if (!urls.length) {
      PE.toast.warning('Enter at least one target URL');
      return;
    }

    const profile = this._profileSelect.value;
    const checks = this._checksInput.value.trim()
      ? this._checksInput.value.split(',').map(c => c.trim()).filter(Boolean)
      : null;

    this._startScanBtn.disabled = true;
    this._startScanBtn.textContent = 'Starting...';

    try {
      await PE.api.post('/api/scanner/scan', {
        urls: urls,
        profile: profile,
        checks: checks,
      });
      PE.toast.success('Scan started');
      this._urlInput.value = '';
      this._scanForm.style.display = 'none';
      this._toggleFormBtn.textContent = 'Expand';
      this._refreshScans();
    } catch (e) {
      PE.toast.error('Failed to start scan: ' + e.message);
    } finally {
      this._startScanBtn.disabled = false;
      this._startScanBtn.textContent = 'Start Scan';
    }
  },

  async _stopScan(scanId) {
    try {
      await PE.api.post(`/api/scanner/scan/${scanId}/stop`);
      PE.toast.info('Scan stopping...');
      this._refreshScans();
    } catch (e) {
      PE.toast.error('Failed to stop scan: ' + e.message);
    }
  },

  _scanFlow(flow) {
    if (!flow) return;
    const url = flow.request?.url || flow.url || '';
    this._urlInput.value = url;
    this._scanForm.style.display = '';
    this._toggleFormBtn.textContent = 'Collapse';
    PE.tabManager.switchTo('scanner');
  },

  _showFindingDetail(finding) {
    if (!finding) return;

    const body = PE.el('div', { class: 'scanner-finding-detail' });

    // Severity badge
    const sevRow = PE.el('div', { class: 'finding-detail-row' });
    const sev = (finding.severity || 'info').toLowerCase();
    sevRow.appendChild(PE.el('span', { class: `badge sev-${sev} finding-detail-sev`, text: sev.charAt(0).toUpperCase() + sev.slice(1) }));
    if (finding.confidence) {
      sevRow.appendChild(PE.el('span', { class: `confidence-badge confidence-${finding.confidence.toLowerCase()}`, text: finding.confidence }));
    }
    body.appendChild(sevRow);

    // Name
    body.appendChild(PE.el('h3', { class: 'finding-detail-name', text: finding.name || 'Unnamed Finding' }));

    // URL
    if (finding.url) {
      const urlRow = PE.el('div', { class: 'finding-detail-row' });
      urlRow.appendChild(PE.el('strong', { text: 'URL: ' }));
      const urlLink = PE.el('span', { class: 'finding-detail-url', text: finding.url });
      urlLink.addEventListener('click', () => PE.utils.copyToClipboard(finding.url));
      urlRow.appendChild(urlLink);
      body.appendChild(urlRow);
    }

    // Source
    if (finding.source) {
      body.appendChild(PE.el('div', { class: 'finding-detail-row' },
        PE.el('strong', { text: 'Source: ' }),
        PE.el('span', { text: finding.source }),
      ));
    }

    // Description
    if (finding.description) {
      body.appendChild(PE.el('div', { class: 'finding-detail-section' },
        PE.el('h4', { text: 'Description' }),
        PE.el('div', { class: 'finding-detail-text', text: finding.description }),
      ));
    }

    // Evidence / details
    if (finding.evidence || finding.detail) {
      body.appendChild(PE.el('div', { class: 'finding-detail-section' },
        PE.el('h4', { text: 'Evidence' }),
        PE.el('pre', { class: 'finding-detail-evidence', text: finding.evidence || finding.detail }),
      ));
    }

    // Remediation
    if (finding.remediation) {
      body.appendChild(PE.el('div', { class: 'finding-detail-section' },
        PE.el('h4', { text: 'Remediation' }),
        PE.el('div', { class: 'finding-detail-text', text: finding.remediation }),
      ));
    }

    // References
    if (finding.references && finding.references.length) {
      const refsSection = PE.el('div', { class: 'finding-detail-section' });
      refsSection.appendChild(PE.el('h4', { text: 'References' }));
      const refList = PE.el('ul', { class: 'finding-detail-refs' });
      for (const ref of finding.references) {
        const li = PE.el('li');
        li.appendChild(PE.el('a', { href: ref, target: '_blank', rel: 'noopener', text: ref }));
        refList.appendChild(li);
      }
      refsSection.appendChild(refList);
      body.appendChild(refsSection);
    }

    // cURL command
    const curlSection = PE.el('div', { class: 'finding-detail-section' });
    curlSection.appendChild(PE.el('h4', { text: 'Reproduce (cURL)' }));
    const curl = PE.utils.buildCurl(
      finding.method || 'GET',
      finding.url || '',
      finding.request_headers || {},
      finding.request_body || null,
    );
    const curlPre = PE.el('pre', { class: 'finding-detail-curl', text: curl });
    curlPre.addEventListener('click', () => PE.utils.copyToClipboard(curl));
    curlSection.appendChild(curlPre);
    body.appendChild(curlSection);

    // Footer buttons
    const sendToRepeater = PE.el('button', { class: 'btn btn-sm', text: 'Send to Repeater' });
    sendToRepeater.addEventListener('click', () => {
      PE.bus.emit('flow:sendToRepeater', {
        request: {
          method: finding.method || 'GET',
          url: finding.url || '',
          headers: finding.request_headers || {},
          body: finding.request_body || '',
        },
      });
    });

    const copyBtn = PE.el('button', { class: 'btn btn-sm', text: 'Copy cURL' });
    copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(curl));

    PE.modal.show({
      title: finding.name || 'Finding Detail',
      body: body,
      footer: [sendToRepeater, copyBtn],
      width: '700px',
    });
  },

  _findingContextMenu(finding, e) {
    if (!finding) return;
    PE.contextMenu.show(e.clientX, e.clientY, [
      { label: 'View Details', action: () => this._showFindingDetail(finding) },
      { label: 'Send to Repeater', action: () => {
        PE.bus.emit('flow:sendToRepeater', {
          request: {
            method: finding.method || 'GET',
            url: finding.url || '',
            headers: finding.request_headers || {},
            body: finding.request_body || '',
          },
        });
      }},
      { label: 'Copy URL', action: () => PE.utils.copyToClipboard(finding.url || '') },
      { label: 'Copy as cURL', action: () => {
        const curl = PE.utils.buildCurl(finding.method || 'GET', finding.url || '', finding.request_headers || {}, finding.request_body || null);
        PE.utils.copyToClipboard(curl);
      }},
      'separator',
      { label: 'Mark as False Positive', action: () => this._markFalsePositive(finding) },
    ]);
  },

  async _markFalsePositive(finding) {
    try {
      await PE.api.patch(`/api/scanner/findings/${finding.id}`, { false_positive: true });
      this._allFindings = this._allFindings.filter(f => f.id !== finding.id);
      this._applyFilters();
      this._updateSeverityCounts();
      PE.toast.success('Marked as false positive');
    } catch (e) {
      PE.toast.error('Failed to mark finding: ' + e.message);
    }
  },

  async _compareScansDiff() {
    const idA = this._compareA.value;
    const idB = this._compareB.value;
    if (!idA || !idB) {
      PE.toast.warning('Select two scans to compare');
      return;
    }
    if (idA === idB) {
      PE.toast.warning('Select two different scans');
      return;
    }

    try {
      const diff = await PE.api.get('/api/scanner/diff', { scan_a: idA, scan_b: idB });
      this._showDiffModal(diff);
    } catch (e) {
      PE.toast.error('Diff failed: ' + e.message);
    }
  },

  _showDiffModal(diff) {
    const body = PE.el('div', { class: 'scanner-diff' });

    const addedFindings = diff.added || [];
    const removedFindings = diff.removed || [];
    const unchangedCount = diff.unchanged_count || 0;

    body.appendChild(PE.el('div', { class: 'diff-summary' },
      PE.el('span', { class: 'diff-added', text: `+${addedFindings.length} new` }),
      PE.el('span', { text: ' | ' }),
      PE.el('span', { class: 'diff-removed', text: `-${removedFindings.length} resolved` }),
      PE.el('span', { text: ' | ' }),
      PE.el('span', { class: 'diff-unchanged', text: `${unchangedCount} unchanged` }),
    ));

    if (addedFindings.length) {
      body.appendChild(PE.el('h4', { text: 'New Findings' }));
      for (const f of addedFindings) {
        const sev = (f.severity || 'info').toLowerCase();
        body.appendChild(PE.el('div', { class: 'diff-finding-item diff-added-item' },
          PE.el('span', { class: `badge sev-${sev}`, text: sev }),
          PE.el('span', { text: f.name || '' }),
          PE.el('span', { class: 'diff-finding-url', text: PE.utils.truncate(f.url || '', 50) }),
        ));
      }
    }

    if (removedFindings.length) {
      body.appendChild(PE.el('h4', { text: 'Resolved Findings' }));
      for (const f of removedFindings) {
        const sev = (f.severity || 'info').toLowerCase();
        body.appendChild(PE.el('div', { class: 'diff-finding-item diff-removed-item' },
          PE.el('span', { class: `badge sev-${sev}`, text: sev }),
          PE.el('span', { text: f.name || '' }),
          PE.el('span', { class: 'diff-finding-url', text: PE.utils.truncate(f.url || '', 50) }),
        ));
      }
    }

    PE.modal.show({
      title: 'Scan Comparison',
      body: body,
      width: '700px',
    });
  },
};
