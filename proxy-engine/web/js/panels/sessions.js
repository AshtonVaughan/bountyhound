/**
 * Sessions Panel — Session rules and macro chain editor.
 */
PE.panels = PE.panels || {};

PE.panels.sessions = {
  _container: null,
  _els: {},
  _rules: [],
  _chains: [],
  _selectedChainIdx: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('sessions-panel');

    // ── Split: rules left, chain editor right ─────────────────────────────
    const splitWrap = PE.el('div', { class: 'split-container', style: { display: 'flex', height: '100%' } });

    const leftPane = PE.el('div', { class: 'split-pane' });
    const rightPane = PE.el('div', { class: 'split-pane' });

    // ── Left: Session Rules ───────────────────────────────────────────────
    const rulesHeader = PE.el('div', { class: 'panel-section-header' });
    rulesHeader.appendChild(PE.el('h3', { text: 'Session Rules' }));
    const addRuleBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Add Rule' });
    addRuleBtn.addEventListener('click', () => this._showAddRuleDialog());
    rulesHeader.appendChild(addRuleBtn);
    leftPane.appendChild(rulesHeader);

    this._els.rulesTableWrap = PE.el('div', { class: 'table-wrap', style: { flex: '1', overflow: 'auto' } });
    leftPane.appendChild(this._els.rulesTableWrap);

    this._rulesTable = new PE.VirtualTable(this._els.rulesTableWrap, {
      columns: [
        { key: 'enabled', label: 'On', width: '50px', render: (v) => `<input type="checkbox" ${v ? 'checked' : ''} class="rule-toggle">` },
        { key: 'name', label: 'Name', flex: '1', sortable: true },
        { key: 'trigger', label: 'Trigger', flex: '1', sortable: true },
        { key: 'scope', label: 'Scope', width: '120px', sortable: true },
        { key: '_actions', label: '', width: '80px', render: (_, row) =>
          `<button class="btn btn-xs btn-ghost rule-test" data-idx="${row._idx}">Test</button>` +
          `<button class="btn btn-xs btn-ghost btn-danger rule-remove" data-idx="${row._idx}">&times;</button>`
        },
      ],
      rowHeight: 32,
      getId: (row) => row._idx,
      onRowClick: (row) => this._selectRule(row),
    });

    this._els.rulesTableWrap.addEventListener('click', (e) => {
      const testBtn = e.target.closest('.rule-test');
      if (testBtn) {
        this._testRule(parseInt(testBtn.dataset.idx));
        return;
      }
      const removeBtn = e.target.closest('.rule-remove');
      if (removeBtn) {
        this._removeRule(parseInt(removeBtn.dataset.idx));
        return;
      }
    });

    this._els.rulesTableWrap.addEventListener('change', (e) => {
      if (e.target.classList.contains('rule-toggle')) {
        const row = e.target.closest('.virtual-table-row');
        if (row) this._toggleRule(row.dataset.rowId, e.target.checked);
      }
    });

    // ── Chains Section (below rules) ──────────────────────────────────────
    const chainsHeader = PE.el('div', { class: 'panel-section-header', style: { marginTop: '12px' } });
    chainsHeader.appendChild(PE.el('h3', { text: 'Macro Chains' }));
    const addChainBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Add Chain' });
    addChainBtn.addEventListener('click', () => this._showAddChainDialog());
    chainsHeader.appendChild(addChainBtn);
    leftPane.appendChild(chainsHeader);

    this._els.chainsList = PE.el('div', { class: 'chains-list', style: { flex: '1', overflow: 'auto' } });
    leftPane.appendChild(this._els.chainsList);

    // ── Right: Chain Editor ───────────────────────────────────────────────
    const editorHeader = PE.el('div', { class: 'panel-section-header' });
    editorHeader.appendChild(PE.el('h3', { text: 'Chain Editor' }));
    rightPane.appendChild(editorHeader);

    this._els.editorEmpty = PE.el('div', { class: 'empty-state', style: { padding: '40px' } },
      PE.el('div', { class: 'title', text: 'Select a chain to edit' }),
      PE.el('div', { text: 'Choose a macro chain from the left panel' })
    );
    rightPane.appendChild(this._els.editorEmpty);

    this._els.editorContent = PE.el('div', { class: 'chain-editor', style: { display: 'none', flex: '1', overflow: 'auto', padding: '8px' } });
    rightPane.appendChild(this._els.editorContent);

    this._els.extractedVars = PE.el('div', { class: 'extracted-vars', style: { display: 'none', padding: '8px', borderTop: '1px solid var(--border)' } });
    this._els.extractedVars.appendChild(PE.el('h4', { text: 'Extracted Variables', style: { marginBottom: '6px' } }));
    this._els.extractedVarsBody = PE.el('div', { class: 'vars-body' });
    this._els.extractedVars.appendChild(this._els.extractedVarsBody);
    rightPane.appendChild(this._els.extractedVars);

    splitWrap.appendChild(leftPane);
    splitWrap.appendChild(PE.el('div', { class: 'split-handle' }));
    splitWrap.appendChild(rightPane);
    container.appendChild(splitWrap);

    new PE.SplitPane(splitWrap, { direction: 'horizontal', initialRatio: 0.4, storageKey: 'sessions-split' });

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'sessions') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const [rulesData, chainsData] = await Promise.all([
        PE.api.get('/api/sessions/rules'),
        PE.api.get('/api/sessions/chains'),
      ]);
      this._rules = (rulesData.rules || rulesData || []).map((r, i) => ({ ...r, _idx: i }));
      this._chains = chainsData.chains || chainsData || [];
      this._rulesTable.setData(this._rules);
      this._renderChainsList();
    } catch (e) {
      console.error('[sessions] refresh failed:', e);
    }
  },

  _renderChainsList() {
    this._els.chainsList.innerHTML = '';
    if (!this._chains.length) {
      this._els.chainsList.appendChild(PE.el('div', { class: 'empty-state', style: { padding: '20px' } },
        PE.el('div', { class: 'title', text: 'No macro chains' })
      ));
      return;
    }
    this._chains.forEach((chain, idx) => {
      const item = PE.el('div', {
        class: 'chain-list-item' + (this._selectedChainIdx === idx ? ' selected' : ''),
        style: { padding: '8px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border)' },
      });
      item.appendChild(PE.el('span', { text: chain.name || `Chain ${idx + 1}` }));

      const actions = PE.el('div', { style: { display: 'flex', gap: '4px' } });
      const execBtn = PE.el('button', { class: 'btn btn-xs btn-primary', text: 'Execute' });
      execBtn.addEventListener('click', (e) => { e.stopPropagation(); this._executeChain(idx); });
      actions.appendChild(execBtn);

      const delBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: '\u00D7' });
      delBtn.addEventListener('click', (e) => { e.stopPropagation(); this._removeChain(idx); });
      actions.appendChild(delBtn);

      item.appendChild(actions);
      item.addEventListener('click', () => this._selectChain(idx));
      this._els.chainsList.appendChild(item);
    });
  },

  _selectRule(rule) {
    // Highlight selected rule, no additional action needed
  },

  async _toggleRule(idxStr, enabled) {
    const idx = parseInt(idxStr);
    try {
      await PE.api.patch(`/api/sessions/rules/${idx}`, { enabled });
      PE.toast.success(`Rule ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle rule: ' + e.message);
    }
  },

  async _testRule(idx) {
    try {
      const result = await PE.api.post(`/api/sessions/rules/${idx}/test`, {});
      PE.modal.show({
        title: 'Rule Test Result',
        body: PE.el('pre', { class: 'syntax-hl', html: PE.syntax.highlightJSON(JSON.stringify(result, null, 2)) }),
        width: '500px',
      });
    } catch (e) {
      PE.toast.error('Test failed: ' + e.message);
    }
  },

  async _removeRule(idx) {
    const confirmed = await PE.modal.confirm({
      title: 'Remove Rule',
      message: `Remove session rule "${this._rules[idx]?.name || idx}"?`,
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await PE.api.del(`/api/sessions/rules/${idx}`);
      PE.toast.success('Rule removed');
      this.refresh();
    } catch (e) {
      PE.toast.error('Failed to remove rule: ' + e.message);
    }
  },

  _showAddRuleDialog() {
    const form = PE.el('div', { class: 'form-grid', style: { display: 'grid', gap: '8px' } });

    const nameInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'Rule name' });
    const triggerInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'Trigger pattern (e.g. status:401)' });
    const scopeSelect = PE.el('select', { class: 'input' });
    ['all', 'in-scope', 'custom'].forEach(s => {
      scopeSelect.appendChild(PE.el('option', { value: s, text: s }));
    });

    form.appendChild(PE.el('label', { text: 'Name' }));
    form.appendChild(nameInput);
    form.appendChild(PE.el('label', { text: 'Trigger' }));
    form.appendChild(triggerInput);
    form.appendChild(PE.el('label', { text: 'Scope' }));
    form.appendChild(scopeSelect);

    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: 'Save Rule' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: 'Add Session Rule',
      body: form,
      footer: [cancelBtn, saveBtn],
      width: '450px',
    });

    cancelBtn.addEventListener('click', () => close());
    saveBtn.addEventListener('click', async () => {
      if (!nameInput.value.trim()) { PE.toast.warning('Name is required'); return; }
      try {
        await PE.api.post('/api/sessions/rules', {
          name: nameInput.value.trim(),
          trigger: triggerInput.value.trim(),
          scope: scopeSelect.value,
          enabled: true,
        });
        close();
        PE.toast.success('Rule added');
        this.refresh();
      } catch (e) {
        PE.toast.error('Failed to add rule: ' + e.message);
      }
    });
  },

  _showAddChainDialog() {
    const nameInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'Chain name' });
    const form = PE.el('div', { style: { padding: '4px 0' } });
    form.appendChild(PE.el('label', { text: 'Chain Name', style: { display: 'block', marginBottom: '4px' } }));
    form.appendChild(nameInput);

    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: 'Create' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: 'New Macro Chain',
      body: form,
      footer: [cancelBtn, saveBtn],
      width: '400px',
    });

    cancelBtn.addEventListener('click', () => close());
    saveBtn.addEventListener('click', async () => {
      if (!nameInput.value.trim()) { PE.toast.warning('Name is required'); return; }
      try {
        await PE.api.post('/api/sessions/chains', { name: nameInput.value.trim(), steps: [] });
        close();
        PE.toast.success('Chain created');
        this.refresh();
      } catch (e) {
        PE.toast.error('Failed to create chain: ' + e.message);
      }
    });
  },

  _selectChain(idx) {
    this._selectedChainIdx = idx;
    this._renderChainsList();
    this._renderChainEditor(idx);
  },

  _renderChainEditor(idx) {
    const chain = this._chains[idx];
    if (!chain) return;

    this._els.editorEmpty.style.display = 'none';
    this._els.editorContent.style.display = '';
    this._els.editorContent.innerHTML = '';

    const steps = chain.steps || [];

    // Chain name
    const nameRow = PE.el('div', { style: { marginBottom: '12px', display: 'flex', gap: '8px', alignItems: 'center' } });
    nameRow.appendChild(PE.el('strong', { text: chain.name || `Chain ${idx + 1}` }));
    nameRow.appendChild(PE.el('span', { text: `(${steps.length} step${steps.length !== 1 ? 's' : ''})`, style: { color: 'var(--text-muted)' } }));
    this._els.editorContent.appendChild(nameRow);

    // Steps
    steps.forEach((step, sIdx) => {
      const stepEl = this._buildStepEditor(step, sIdx, idx);
      this._els.editorContent.appendChild(stepEl);
    });

    // Add step button
    const addStepBtn = PE.el('button', { class: 'btn btn-sm', text: '+ Add Step', style: { marginTop: '8px' } });
    addStepBtn.addEventListener('click', () => {
      steps.push({ method: 'GET', url: '', headers: {}, body: '', extract: [] });
      this._saveChainSteps(idx, steps);
    });
    this._els.editorContent.appendChild(addStepBtn);
  },

  _buildStepEditor(step, stepIdx, chainIdx) {
    const wrapper = PE.el('div', {
      class: 'chain-step',
      style: { border: '1px solid var(--border)', borderRadius: '4px', padding: '10px', marginBottom: '8px', background: 'var(--bg-raised, var(--bg-secondary))' },
    });

    const headerRow = PE.el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' } });
    headerRow.appendChild(PE.el('span', { text: `Step ${stepIdx + 1}`, style: { fontWeight: '600', fontSize: '12px' } }));

    const removeStepBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: '\u00D7', style: { marginLeft: 'auto' } });
    removeStepBtn.addEventListener('click', () => {
      const chain = this._chains[chainIdx];
      chain.steps.splice(stepIdx, 1);
      this._saveChainSteps(chainIdx, chain.steps);
    });
    headerRow.appendChild(removeStepBtn);
    wrapper.appendChild(headerRow);

    // Method + URL row
    const reqRow = PE.el('div', { style: { display: 'flex', gap: '6px', marginBottom: '6px' } });
    const methodSelect = PE.el('select', { class: 'input', style: { width: '90px' } });
    ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].forEach(m => {
      const opt = PE.el('option', { value: m, text: m });
      if (m === (step.method || 'GET')) opt.selected = true;
      methodSelect.appendChild(opt);
    });
    methodSelect.addEventListener('change', () => { step.method = methodSelect.value; });
    reqRow.appendChild(methodSelect);

    const urlInput = PE.el('input', { type: 'text', class: 'input', value: step.url || '', placeholder: 'https://example.com/api/login', style: { flex: '1' } });
    urlInput.addEventListener('input', () => { step.url = urlInput.value; });
    reqRow.appendChild(urlInput);
    wrapper.appendChild(reqRow);

    // Headers textarea
    wrapper.appendChild(PE.el('label', { text: 'Headers (JSON)', style: { fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '2px' } }));
    const headersTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '50px', resize: 'vertical', fontFamily: 'monospace', fontSize: '12px' },
    });
    headersTA.value = typeof step.headers === 'object' ? JSON.stringify(step.headers, null, 2) : (step.headers || '{}');
    headersTA.addEventListener('change', () => {
      try { step.headers = JSON.parse(headersTA.value); } catch (_) { PE.toast.warning('Invalid JSON for headers'); }
    });
    wrapper.appendChild(headersTA);

    // Body textarea
    wrapper.appendChild(PE.el('label', { text: 'Body', style: { fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginTop: '6px', marginBottom: '2px' } }));
    const bodyTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '40px', resize: 'vertical', fontFamily: 'monospace', fontSize: '12px' },
    });
    bodyTA.value = step.body || '';
    bodyTA.addEventListener('change', () => { step.body = bodyTA.value; });
    wrapper.appendChild(bodyTA);

    // Extract config
    wrapper.appendChild(PE.el('label', { text: 'Extract (name:regex per line)', style: { fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginTop: '6px', marginBottom: '2px' } }));
    const extractTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '36px', resize: 'vertical', fontFamily: 'monospace', fontSize: '12px' },
    });
    const extractArr = step.extract || [];
    extractTA.value = extractArr.map(e => `${e.name}:${e.regex || e.pattern || ''}`).join('\n');
    extractTA.addEventListener('change', () => {
      step.extract = extractTA.value.split('\n').filter(l => l.trim()).map(line => {
        const colonIdx = line.indexOf(':');
        return colonIdx > 0
          ? { name: line.slice(0, colonIdx).trim(), regex: line.slice(colonIdx + 1).trim() }
          : { name: line.trim(), regex: '' };
      });
    });
    wrapper.appendChild(extractTA);

    return wrapper;
  },

  async _saveChainSteps(chainIdx, steps) {
    try {
      await PE.api.put(`/api/sessions/chains/${chainIdx}`, { ...this._chains[chainIdx], steps });
      PE.toast.success('Chain updated');
      this.refresh().then(() => {
        if (this._selectedChainIdx === chainIdx) this._renderChainEditor(chainIdx);
      });
    } catch (e) {
      PE.toast.error('Failed to save chain: ' + e.message);
    }
  },

  async _executeChain(idx) {
    try {
      PE.toast.info('Executing chain...');
      const result = await PE.api.post(`/api/sessions/chains/${idx}/execute`, {});
      PE.toast.success('Chain executed');

      // Show extracted variables
      const vars = result.extracted || result.variables || {};
      if (Object.keys(vars).length) {
        this._els.extractedVars.style.display = '';
        this._els.extractedVarsBody.innerHTML = '';
        for (const [name, value] of Object.entries(vars)) {
          const row = PE.el('div', { style: { display: 'flex', gap: '8px', padding: '3px 0', fontFamily: 'monospace', fontSize: '12px' } });
          row.appendChild(PE.el('span', { text: name + ':', style: { color: 'var(--accent)', fontWeight: '600' } }));
          row.appendChild(PE.el('span', { text: String(value), style: { wordBreak: 'break-all' } }));
          this._els.extractedVarsBody.appendChild(row);
        }
      }

      // Show full result in modal
      PE.modal.show({
        title: 'Chain Execution Result',
        body: PE.el('pre', { class: 'syntax-hl', html: PE.syntax.highlightJSON(JSON.stringify(result, null, 2)) }),
        width: '600px',
      });
    } catch (e) {
      PE.toast.error('Chain execution failed: ' + e.message);
    }
  },

  async _removeChain(idx) {
    const confirmed = await PE.modal.confirm({
      title: 'Remove Chain',
      message: `Remove macro chain "${this._chains[idx]?.name || idx}"?`,
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await PE.api.del(`/api/sessions/chains/${idx}`);
      PE.toast.success('Chain removed');
      if (this._selectedChainIdx === idx) {
        this._selectedChainIdx = null;
        this._els.editorContent.style.display = 'none';
        this._els.editorEmpty.style.display = '';
        this._els.extractedVars.style.display = 'none';
      }
      this.refresh();
    } catch (e) {
      PE.toast.error('Failed to remove chain: ' + e.message);
    }
  },
};
