/**
 * Passive Panel — Passive findings table with grouping, severity filter, false-positive marking.
 */
PE.panels = PE.panels || {};

PE.panels.passive = {
  _container: null,
  _table: null,
  _findings: [],
  _sevFilter: 'all',
  _grouped: false,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('passive-panel');

    // ── Toolbar ────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar' });

    // Toggle passive scanning
    this._toggleBtn = PE.el('button', { class: 'btn btn-sm', text: 'Passive: ON' });
    this._toggleBtn.addEventListener('click', () => this._togglePassive());
    toolbar.appendChild(this._toggleBtn);

    // Severity filter
    const sevSelect = PE.el('select', { class: 'input input-sm' });
    for (const sev of ['all', 'critical', 'high', 'medium', 'low', 'info']) {
      sevSelect.appendChild(PE.el('option', { value: sev, text: sev.charAt(0).toUpperCase() + sev.slice(1) }));
    }
    sevSelect.addEventListener('change', () => {
      this._sevFilter = sevSelect.value;
      this._applyFilter();
    });
    toolbar.appendChild(PE.el('label', { class: 'toolbar-label', text: 'Severity:' }));
    toolbar.appendChild(sevSelect);

    // Group by check_id
    const groupBtn = PE.el('button', { class: 'btn btn-sm', text: 'Group by Check' });
    groupBtn.addEventListener('click', () => {
      this._grouped = !this._grouped;
      groupBtn.classList.toggle('active', this._grouped);
      this._applyFilter();
    });
    toolbar.appendChild(groupBtn);

    // Mark false positive
    const fpBtn = PE.el('button', { class: 'btn btn-sm', text: 'Mark False Positive' });
    fpBtn.addEventListener('click', () => this._markFalsePositive());
    toolbar.appendChild(fpBtn);

    // Clear findings
    const clearBtn = PE.el('button', { class: 'btn btn-sm btn-danger', text: 'Clear' });
    clearBtn.addEventListener('click', async () => {
      const ok = await PE.modal.confirm({
        title: 'Clear Findings',
        message: 'Remove all passive findings?',
        confirmLabel: 'Clear All',
        danger: true,
      });
      if (ok) {
        try {
          await PE.api.del('/api/passive/findings');
          this._findings = [];
          this._table.setData([]);
          PE.toast.success('Findings cleared');
        } catch (e) {
          PE.toast.error('Failed to clear findings: ' + e.message);
        }
      }
    });
    toolbar.appendChild(clearBtn);

    // Count label
    this._countLabel = PE.el('span', { class: 'toolbar-count', text: '0 findings' });
    toolbar.appendChild(this._countLabel);

    container.appendChild(toolbar);

    // ── Split: table + detail ──────────────────────────────────────────────
    const splitWrap = PE.el('div', { class: 'split-container', style: { flex: '1', display: 'flex', flexDirection: 'column' } });

    const tableWrap = PE.el('div', { class: 'split-pane', style: { flex: '1', display: 'flex', flexDirection: 'column', overflow: 'hidden' } });
    this._detailPane = PE.el('div', { class: 'split-pane passive-detail', style: { height: '220px', overflow: 'auto', borderTop: '1px solid var(--border)' } });

    splitWrap.appendChild(tableWrap);
    splitWrap.appendChild(this._detailPane);
    container.appendChild(splitWrap);

    // ── VirtualTable ───────────────────────────────────────────────────────
    this._table = new PE.VirtualTable(tableWrap, {
      columns: [
        {
          key: 'severity', label: 'Severity', width: '90px', sortable: true,
          render: (val) => `<span class="badge ${PE.utils.sevClass(val)}">${PE.utils.escapeHtml(val || 'info')}</span>`,
        },
        { key: 'check_id', label: 'Check ID', width: '140px', sortable: true },
        { key: 'name', label: 'Name', flex: '1', sortable: true },
        {
          key: 'url', label: 'URL', flex: '1.5', sortable: true,
          render: (val) => `<span title="${PE.utils.escapeHtml(val || '')}">${PE.utils.escapeHtml(PE.utils.truncate(val, 80))}</span>`,
        },
        {
          key: 'evidence', label: 'Evidence', flex: '1',
          render: (val) => `<span class="evidence-preview">${PE.utils.escapeHtml(PE.utils.truncate(val, 60))}</span>`,
        },
      ],
      onRowClick: (row) => this._showDetail(row),
      onRowContext: (row, e) => this._showContextMenu(row, e),
      getId: (row) => row.id || row.finding_id || PE.utils.genId(),
    });

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('finding:new', (finding) => {
      if (finding && finding.source === 'passive') {
        this._findings.push(finding);
        this._applyFilter();
      }
    });

    PE.bus.on('panel:activated', (id) => {
      if (id === 'passive') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/passive/findings');
      this._findings = Array.isArray(data) ? data : (data.findings || []);
      this._applyFilter();
      this._updateToggleState();
    } catch (e) {
      console.error('[passive] refresh failed:', e);
    }
  },

  _applyFilter() {
    let filtered = this._findings;

    // Severity filter
    if (this._sevFilter !== 'all') {
      filtered = filtered.filter(f => (f.severity || 'info').toLowerCase() === this._sevFilter);
    }

    // Exclude false positives
    filtered = filtered.filter(f => !f.false_positive);

    // Sort by severity
    filtered.sort((a, b) => PE.utils.sevOrder(a.severity) - PE.utils.sevOrder(b.severity));

    // Group by check_id if enabled
    if (this._grouped) {
      const groups = {};
      for (const f of filtered) {
        const key = f.check_id || 'unknown';
        if (!groups[key]) groups[key] = [];
        groups[key].push(f);
      }
      const grouped = [];
      for (const [checkId, items] of Object.entries(groups)) {
        // Insert group header row
        grouped.push({
          id: '__group__' + checkId,
          severity: items[0].severity,
          check_id: checkId,
          name: `${items[0].name || checkId} (${items.length} findings)`,
          url: '',
          evidence: '',
          _isGroup: true,
          _items: items,
          highlight: 'group',
        });
        for (const item of items) {
          grouped.push(item);
        }
      }
      filtered = grouped;
    }

    this._table.setData(filtered);
    this._countLabel.textContent = `${this._findings.filter(f => !f.false_positive).length} findings`;
  },

  _showDetail(row) {
    if (!row || row._isGroup) {
      this._detailPane.innerHTML = '';
      return;
    }

    const esc = PE.utils.escapeHtml;
    this._detailPane.innerHTML = `
      <div class="detail-header">
        <span class="badge ${PE.utils.sevClass(row.severity)}">${esc(row.severity || 'info')}</span>
        <strong>${esc(row.name || row.check_id || '')}</strong>
      </div>
      <div class="detail-section">
        <div class="detail-label">Check ID</div>
        <div class="detail-value">${esc(row.check_id || '')}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">URL</div>
        <div class="detail-value url-value">${esc(row.url || '')}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Evidence</div>
        <pre class="detail-evidence">${esc(row.evidence || row.detail || 'No evidence recorded')}</pre>
      </div>
      ${row.description ? `<div class="detail-section"><div class="detail-label">Description</div><div class="detail-value">${esc(row.description)}</div></div>` : ''}
      ${row.remediation ? `<div class="detail-section"><div class="detail-label">Remediation</div><div class="detail-value">${esc(row.remediation)}</div></div>` : ''}
      ${row.flow_id ? `<div class="detail-section"><div class="detail-label">Flow ID</div><div class="detail-value"><a href="#" class="flow-link" data-flow-id="${esc(row.flow_id)}">${esc(row.flow_id)}</a></div></div>` : ''}
    `;

    // Flow link click handler
    const flowLink = this._detailPane.querySelector('.flow-link');
    if (flowLink) {
      flowLink.addEventListener('click', (e) => {
        e.preventDefault();
        PE.bus.emit('flow:select', flowLink.dataset.flowId);
      });
    }
  },

  _showContextMenu(row, e) {
    if (!row || row._isGroup) return;
    PE.contextMenu.show(e.clientX, e.clientY, [
      { label: 'View Details', action: () => this._showDetail(row) },
      { label: 'Copy URL', action: () => PE.utils.copyToClipboard(row.url || '') },
      { label: 'Copy Evidence', action: () => PE.utils.copyToClipboard(row.evidence || '') },
      'separator',
      { label: 'Mark False Positive', action: () => this._markFP(row) },
      { label: 'Send to Repeater', action: () => {
        if (row.flow_id) PE.bus.emit('flow:sendToRepeater', { id: row.flow_id });
      }},
      'separator',
      { label: 'View Flow', disabled: !row.flow_id, action: () => PE.bus.emit('flow:select', row.flow_id) },
    ]);
  },

  async _markFalsePositive() {
    const selected = this._table.getSelected();
    if (!selected || selected._isGroup) {
      PE.toast.warning('Select a finding first');
      return;
    }
    await this._markFP(selected);
  },

  async _markFP(finding) {
    try {
      await PE.api.patch(`/api/passive/findings/${finding.id || finding.finding_id}`, { false_positive: true });
      finding.false_positive = true;
      this._applyFilter();
      PE.toast.success('Marked as false positive');
    } catch (e) {
      PE.toast.error('Failed to mark false positive: ' + e.message);
    }
  },

  async _togglePassive() {
    try {
      const status = await PE.api.post('/api/passive/toggle');
      const enabled = status.enabled !== false;
      this._toggleBtn.textContent = `Passive: ${enabled ? 'ON' : 'OFF'}`;
      this._toggleBtn.classList.toggle('active', enabled);
      PE.toast.info(`Passive scanning ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle passive scanning: ' + e.message);
    }
  },

  async _updateToggleState() {
    try {
      const status = await PE.api.get('/api/passive/status');
      const enabled = status.enabled !== false;
      this._toggleBtn.textContent = `Passive: ${enabled ? 'ON' : 'OFF'}`;
      this._toggleBtn.classList.toggle('active', enabled);
    } catch (_) {}
  },
};
