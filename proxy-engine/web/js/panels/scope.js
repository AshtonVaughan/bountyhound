/**
 * Scope Panel — Include/exclude rule editor with quick-add from observed hosts.
 */
PE.panels = PE.panels || {};

PE.panels.scope = {
  _container: null,
  _includeRules: [],
  _excludeRules: [],
  _scopeEnabled: true,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('scope-panel');

    // ── Toolbar ────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar' });

    // Toggle scope
    this._enableBtn = PE.el('button', { class: 'btn btn-sm active', text: 'Scope: Enabled' });
    this._enableBtn.addEventListener('click', () => this._toggleScope());
    toolbar.appendChild(this._enableBtn);

    // Quick-add from hosts
    const quickAddBtn = PE.el('button', { class: 'btn btn-sm', text: 'Quick Add from Hosts' });
    quickAddBtn.addEventListener('click', () => this._showQuickAdd());
    toolbar.appendChild(quickAddBtn);

    // Import/Export
    const importBtn = PE.el('button', { class: 'btn btn-sm', text: 'Import' });
    importBtn.addEventListener('click', () => this._importScope());
    toolbar.appendChild(importBtn);

    const exportBtn = PE.el('button', { class: 'btn btn-sm', text: 'Export' });
    exportBtn.addEventListener('click', () => this._exportScope());
    toolbar.appendChild(exportBtn);

    container.appendChild(toolbar);

    // ── Include Rules ──────────────────────────────────────────────────────
    const includeCard = PE.el('div', { class: 'panel-card' });
    const includeHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    includeHeader.appendChild(PE.el('span', { text: 'Include Rules' }));

    const addIncludeBtn = PE.el('button', { class: 'btn btn-xs btn-primary', text: '+ Add Rule' });
    addIncludeBtn.addEventListener('click', () => this._showAddRule('include'));
    includeHeader.appendChild(addIncludeBtn);

    includeCard.appendChild(includeHeader);
    this._includeList = PE.el('div', { class: 'scope-rules-list' });
    includeCard.appendChild(this._includeList);
    container.appendChild(includeCard);

    // ── Exclude Rules ──────────────────────────────────────────────────────
    const excludeCard = PE.el('div', { class: 'panel-card' });
    const excludeHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    excludeHeader.appendChild(PE.el('span', { text: 'Exclude Rules' }));

    const addExcludeBtn = PE.el('button', { class: 'btn btn-xs btn-primary', text: '+ Add Rule' });
    addExcludeBtn.addEventListener('click', () => this._showAddRule('exclude'));
    excludeHeader.appendChild(addExcludeBtn);

    excludeCard.appendChild(excludeHeader);
    this._excludeList = PE.el('div', { class: 'scope-rules-list' });
    excludeCard.appendChild(this._excludeList);
    container.appendChild(excludeCard);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'scope') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/scope');
      this._scopeEnabled = data.enabled !== false;
      this._includeRules = data.include || [];
      this._excludeRules = data.exclude || [];
      this._updateToggle();
      this._renderRules();
    } catch (e) {
      console.error('[scope] refresh failed:', e);
    }
  },

  _updateToggle() {
    this._enableBtn.textContent = `Scope: ${this._scopeEnabled ? 'Enabled' : 'Disabled'}`;
    this._enableBtn.classList.toggle('active', this._scopeEnabled);
  },

  async _toggleScope() {
    try {
      const result = await PE.api.post('/api/scope/toggle');
      this._scopeEnabled = result.enabled !== false;
      this._updateToggle();
      PE.toast.info(`Scope ${this._scopeEnabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle scope: ' + e.message);
    }
  },

  _renderRules() {
    this._renderRuleList(this._includeList, this._includeRules, 'include');
    this._renderRuleList(this._excludeList, this._excludeRules, 'exclude');
  },

  _renderRuleList(listEl, rules, type) {
    listEl.innerHTML = '';

    if (rules.length === 0) {
      listEl.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: `No ${type} rules defined` }),
        PE.el('div', { text: type === 'include' ? 'All traffic will be captured' : 'No traffic will be excluded' })
      ));
      return;
    }

    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      const item = PE.el('div', { class: 'scope-rule-item' });

      const ruleInfo = PE.el('div', { class: 'scope-rule-info' });
      ruleInfo.innerHTML = `
        <span class="badge">${PE.utils.escapeHtml(rule.target || 'host')}</span>
        <code class="scope-pattern">${PE.utils.escapeHtml(rule.pattern || '')}</code>
        ${rule.protocol ? `<span class="scope-meta">Proto: ${PE.utils.escapeHtml(rule.protocol)}</span>` : ''}
        ${rule.port ? `<span class="scope-meta">Port: ${PE.utils.escapeHtml(String(rule.port))}</span>` : ''}
        ${rule.path_pattern ? `<span class="scope-meta">Path: ${PE.utils.escapeHtml(rule.path_pattern)}</span>` : ''}
      `;
      item.appendChild(ruleInfo);

      const ruleActions = PE.el('div', { class: 'scope-rule-actions' });

      const editBtn = PE.el('button', { class: 'btn btn-xs', text: 'Edit' });
      editBtn.addEventListener('click', () => this._showEditRule(type, i, rule));
      ruleActions.appendChild(editBtn);

      const removeBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Remove' });
      removeBtn.addEventListener('click', () => this._removeRule(type, i));
      ruleActions.appendChild(removeBtn);

      item.appendChild(ruleActions);
      listEl.appendChild(item);
    }
  },

  _showAddRule(type) {
    this._showRuleForm(type, -1, { pattern: '', target: 'host', protocol: '', port: '', path_pattern: '' });
  },

  _showEditRule(type, index, rule) {
    this._showRuleForm(type, index, { ...rule });
  },

  _showRuleForm(type, index, rule) {
    const form = PE.el('div', { class: 'form-grid' });

    form.appendChild(PE.el('label', { class: 'form-label', text: 'Pattern (regex)' }));
    const patternInput = PE.el('input', { class: 'input', type: 'text', value: rule.pattern || '', placeholder: 'e.g. ^example\\.com$' });
    form.appendChild(patternInput);

    form.appendChild(PE.el('label', { class: 'form-label', text: 'Target' }));
    const targetSelect = PE.el('select', { class: 'input' });
    for (const t of ['host', 'url']) {
      const opt = PE.el('option', { value: t, text: t });
      if (t === (rule.target || 'host')) opt.selected = true;
      targetSelect.appendChild(opt);
    }
    form.appendChild(targetSelect);

    form.appendChild(PE.el('label', { class: 'form-label', text: 'Protocol' }));
    const protoSelect = PE.el('select', { class: 'input' });
    for (const p of ['', 'http', 'https']) {
      const opt = PE.el('option', { value: p, text: p || 'Any' });
      if (p === (rule.protocol || '')) opt.selected = true;
      protoSelect.appendChild(opt);
    }
    form.appendChild(protoSelect);

    form.appendChild(PE.el('label', { class: 'form-label', text: 'Port' }));
    const portInput = PE.el('input', { class: 'input', type: 'text', value: rule.port || '', placeholder: 'e.g. 443, 8080 (empty = any)' });
    form.appendChild(portInput);

    form.appendChild(PE.el('label', { class: 'form-label', text: 'Path Pattern' }));
    const pathInput = PE.el('input', { class: 'input', type: 'text', value: rule.path_pattern || '', placeholder: 'e.g. /api/.* (empty = any)' });
    form.appendChild(pathInput);

    const isEdit = index >= 0;
    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: isEdit ? 'Update Rule' : 'Add Rule' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: `${isEdit ? 'Edit' : 'Add'} ${type.charAt(0).toUpperCase() + type.slice(1)} Rule`,
      body: form,
      footer: [cancelBtn, saveBtn],
    });

    cancelBtn.addEventListener('click', () => close());
    saveBtn.addEventListener('click', async () => {
      const newRule = {
        pattern: patternInput.value.trim(),
        target: targetSelect.value,
        protocol: protoSelect.value || undefined,
        port: portInput.value.trim() || undefined,
        path_pattern: pathInput.value.trim() || undefined,
      };

      if (!newRule.pattern) {
        PE.toast.warning('Pattern is required');
        return;
      }

      // Validate regex
      try {
        new RegExp(newRule.pattern);
      } catch (e) {
        PE.toast.error('Invalid regex pattern: ' + e.message);
        return;
      }

      try {
        if (isEdit) {
          await PE.api.put(`/api/scope/${type}/${index}`, newRule);
        } else {
          await PE.api.post(`/api/scope/${type}`, newRule);
        }
        close();
        this.refresh();
        PE.toast.success(`Rule ${isEdit ? 'updated' : 'added'}`);
      } catch (e) {
        PE.toast.error('Failed to save rule: ' + e.message);
      }
    });
  },

  async _removeRule(type, index) {
    const ok = await PE.modal.confirm({
      title: 'Remove Rule',
      message: 'Remove this scope rule?',
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!ok) return;

    try {
      await PE.api.del(`/api/scope/${type}/${index}`);
      this.refresh();
      PE.toast.success('Rule removed');
    } catch (e) {
      PE.toast.error('Failed to remove rule: ' + e.message);
    }
  },

  async _showQuickAdd() {
    let hosts = [];
    try {
      const data = await PE.api.get('/api/flows/hosts');
      hosts = Array.isArray(data) ? data : (data.hosts || []);
    } catch (e) {
      PE.toast.error('Failed to fetch hosts: ' + e.message);
      return;
    }

    if (hosts.length === 0) {
      PE.toast.info('No hosts observed in flows yet');
      return;
    }

    const body = PE.el('div', { class: 'quick-add-hosts' });
    body.appendChild(PE.el('div', { text: 'Select hosts to add as include rules:', style: { marginBottom: '8px' } }));

    const checkboxes = [];
    for (const host of hosts) {
      const hostName = typeof host === 'string' ? host : (host.host || host.name || '');
      if (!hostName) continue;

      const row = PE.el('div', { class: 'quick-add-row' });
      const cb = PE.el('input', { type: 'checkbox', value: hostName });
      const label = PE.el('label', { text: hostName, style: { marginLeft: '6px', cursor: 'pointer' } });
      label.addEventListener('click', () => { cb.checked = !cb.checked; });
      row.appendChild(cb);
      row.appendChild(label);

      if (typeof host === 'object' && host.flow_count) {
        row.appendChild(PE.el('span', { class: 'toolbar-count', text: `(${host.flow_count} flows)`, style: { marginLeft: 'auto' } }));
      }

      body.appendChild(row);
      checkboxes.push(cb);
    }

    // Select all / none
    const selectAllRow = PE.el('div', { class: 'quick-add-actions', style: { marginTop: '8px' } });
    const selectAll = PE.el('button', { class: 'btn btn-xs', text: 'Select All' });
    selectAll.addEventListener('click', () => checkboxes.forEach(cb => cb.checked = true));
    selectAllRow.appendChild(selectAll);

    const selectNone = PE.el('button', { class: 'btn btn-xs', text: 'Select None' });
    selectNone.addEventListener('click', () => checkboxes.forEach(cb => cb.checked = false));
    selectAllRow.appendChild(selectNone);

    body.appendChild(selectAllRow);

    const addBtn = PE.el('button', { class: 'btn btn-primary', text: 'Add Selected' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: 'Quick Add Hosts to Scope',
      body,
      footer: [cancelBtn, addBtn],
      width: '500px',
    });

    cancelBtn.addEventListener('click', () => close());
    addBtn.addEventListener('click', async () => {
      const selected = checkboxes.filter(cb => cb.checked).map(cb => cb.value);
      if (selected.length === 0) {
        PE.toast.warning('Select at least one host');
        return;
      }

      let added = 0;
      for (const host of selected) {
        try {
          await PE.api.post('/api/scope/include', {
            pattern: host.replace(/\./g, '\\.'),
            target: 'host',
          });
          added++;
        } catch (_) {}
      }

      close();
      this.refresh();
      PE.toast.success(`Added ${added} host rule${added !== 1 ? 's' : ''}`);
    });
  },

  async _exportScope() {
    const data = {
      enabled: this._scopeEnabled,
      include: this._includeRules,
      exclude: this._excludeRules,
    };
    const json = JSON.stringify(data, null, 2);
    PE.utils.copyToClipboard(json);
    PE.toast.success('Scope configuration copied to clipboard');
  },

  async _importScope() {
    const body = PE.el('div', {});
    body.appendChild(PE.el('div', { text: 'Paste scope configuration JSON:', style: { marginBottom: '8px' } }));
    const textarea = PE.el('textarea', { class: 'input', rows: '10', placeholder: '{"include": [...], "exclude": [...]}' });
    body.appendChild(textarea);

    const importBtn = PE.el('button', { class: 'btn btn-primary', text: 'Import' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: 'Import Scope Configuration',
      body,
      footer: [cancelBtn, importBtn],
      width: '500px',
    });

    cancelBtn.addEventListener('click', () => close());
    importBtn.addEventListener('click', async () => {
      try {
        const config = JSON.parse(textarea.value.trim());
        await PE.api.put('/api/scope', config);
        close();
        this.refresh();
        PE.toast.success('Scope configuration imported');
      } catch (e) {
        PE.toast.error('Invalid JSON or import failed: ' + e.message);
      }
    });
  },
};
