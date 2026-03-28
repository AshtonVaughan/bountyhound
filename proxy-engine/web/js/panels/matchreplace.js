/**
 * Match & Replace Panel — Rule editor with inline editing, enable/disable toggle, and test preview.
 */
PE.panels = PE.panels || {};

PE.panels.matchreplace = {
  _container: null,
  _rules: [],

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('matchreplace-panel');

    // ── Toolbar ────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar' });

    const addBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: '+ Add Rule' });
    addBtn.addEventListener('click', () => this._showRuleForm());
    toolbar.appendChild(addBtn);

    // Enable all / disable all
    const enableAllBtn = PE.el('button', { class: 'btn btn-sm', text: 'Enable All' });
    enableAllBtn.addEventListener('click', () => this._setAllEnabled(true));
    toolbar.appendChild(enableAllBtn);

    const disableAllBtn = PE.el('button', { class: 'btn btn-sm', text: 'Disable All' });
    disableAllBtn.addEventListener('click', () => this._setAllEnabled(false));
    toolbar.appendChild(disableAllBtn);

    // Test preview
    const testBtn = PE.el('button', { class: 'btn btn-sm', text: 'Test Rules' });
    testBtn.addEventListener('click', () => this._showTestPreview());
    toolbar.appendChild(testBtn);

    // Count
    this._countLabel = PE.el('span', { class: 'toolbar-count', text: '0 rules' });
    toolbar.appendChild(this._countLabel);

    container.appendChild(toolbar);

    // ── Rules List ─────────────────────────────────────────────────────────
    this._rulesList = PE.el('div', { class: 'mr-rules-list' });
    container.appendChild(this._rulesList);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'matchreplace') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/match-replace/rules');
      this._rules = Array.isArray(data) ? data : (data.rules || []);
      this._renderRules();
    } catch (e) {
      console.error('[matchreplace] refresh failed:', e);
    }
  },

  _renderRules() {
    this._rulesList.innerHTML = '';
    this._countLabel.textContent = `${this._rules.length} rules`;

    if (this._rules.length === 0) {
      this._rulesList.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: 'No match & replace rules' }),
        PE.el('div', { text: 'Add rules to automatically modify proxied traffic' })
      ));
      return;
    }

    for (let i = 0; i < this._rules.length; i++) {
      const rule = this._rules[i];
      this._rulesList.appendChild(this._createRuleCard(rule, i));
    }
  },

  _createRuleCard(rule, index) {
    const card = PE.el('div', { class: `mr-rule-card ${rule.enabled === false ? 'disabled' : ''}` });

    // Header row: name, phase, enabled toggle, actions
    const header = PE.el('div', { class: 'mr-rule-header' });

    // Enable/disable toggle
    const toggleBtn = PE.el('button', {
      class: `btn btn-xs ${rule.enabled !== false ? 'active' : ''}`,
      text: rule.enabled !== false ? 'ON' : 'OFF',
    });
    toggleBtn.addEventListener('click', () => this._toggleRule(index));
    header.appendChild(toggleBtn);

    // Name
    header.appendChild(PE.el('strong', { class: 'mr-rule-name', text: rule.name || `Rule ${index + 1}` }));

    // Phase badge
    header.appendChild(PE.el('span', { class: 'badge mr-phase-badge', text: rule.phase || 'request' }));

    // Is regex indicator
    if (rule.is_regex) {
      header.appendChild(PE.el('span', { class: 'badge', text: 'Regex', style: { background: 'var(--sev-medium, #fcbf49)', color: '#000' } }));
    }

    // Action buttons
    const actions = PE.el('div', { class: 'mr-rule-actions', style: { marginLeft: 'auto' } });

    const editBtn = PE.el('button', { class: 'btn btn-xs', text: 'Edit' });
    editBtn.addEventListener('click', () => this._showRuleForm(rule, index));
    actions.appendChild(editBtn);

    const dupBtn = PE.el('button', { class: 'btn btn-xs', text: 'Duplicate' });
    dupBtn.addEventListener('click', () => this._duplicateRule(rule));
    actions.appendChild(dupBtn);

    const deleteBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Delete' });
    deleteBtn.addEventListener('click', () => this._deleteRule(index));
    actions.appendChild(deleteBtn);

    header.appendChild(actions);
    card.appendChild(header);

    // Rule details
    const details = PE.el('div', { class: 'mr-rule-details' });

    // Target
    details.appendChild(this._detailRow('Target', rule.target || 'body'));

    // Match pattern
    const matchRow = this._detailRow('Match', '');
    const matchCode = PE.el('code', { class: 'mr-pattern', text: rule.match_pattern || '' });
    matchRow.querySelector('.mr-detail-value').appendChild(matchCode);
    details.appendChild(matchRow);

    // Replace
    const replaceRow = this._detailRow('Replace', '');
    const replaceCode = PE.el('code', { class: 'mr-pattern', text: rule.replace || '' });
    replaceRow.querySelector('.mr-detail-value').appendChild(replaceCode);
    details.appendChild(replaceRow);

    // Scope pattern
    if (rule.scope_pattern) {
      details.appendChild(this._detailRow('Scope', rule.scope_pattern));
    }

    card.appendChild(details);
    return card;
  },

  _detailRow(label, value) {
    const row = PE.el('div', { class: 'mr-detail-row' });
    row.appendChild(PE.el('span', { class: 'mr-detail-label', text: label + ':' }));
    const valEl = PE.el('span', { class: 'mr-detail-value' });
    if (typeof value === 'string' && value) valEl.textContent = value;
    row.appendChild(valEl);
    return row;
  },

  _showRuleForm(existingRule, index) {
    const isEdit = existingRule != null;
    const rule = existingRule || { name: '', phase: 'request', target: 'body', match_pattern: '', replace: '', is_regex: false, scope_pattern: '', enabled: true };

    const form = PE.el('div', { class: 'form-grid' });

    // Name
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Name' }));
    const nameInput = PE.el('input', { class: 'input', type: 'text', value: rule.name || '', placeholder: 'Rule name' });
    form.appendChild(nameInput);

    // Phase
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Phase' }));
    const phaseSelect = PE.el('select', { class: 'input' });
    for (const p of ['request', 'response']) {
      const opt = PE.el('option', { value: p, text: p.charAt(0).toUpperCase() + p.slice(1) });
      if (p === (rule.phase || 'request')) opt.selected = true;
      phaseSelect.appendChild(opt);
    }
    form.appendChild(phaseSelect);

    // Target
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Target' }));
    const targetSelect = PE.el('select', { class: 'input' });
    for (const t of ['body', 'header', 'url', 'status', 'first_line', 'param_name', 'param_value']) {
      const opt = PE.el('option', { value: t, text: t.replace(/_/g, ' ') });
      if (t === (rule.target || 'body')) opt.selected = true;
      targetSelect.appendChild(opt);
    }
    form.appendChild(targetSelect);

    // Match pattern
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Match Pattern' }));
    const matchInput = PE.el('input', { class: 'input', type: 'text', value: rule.match_pattern || '', placeholder: 'String or regex to match' });
    form.appendChild(matchInput);

    // Replace
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Replace With' }));
    const replaceInput = PE.el('input', { class: 'input', type: 'text', value: rule.replace || '', placeholder: 'Replacement value (use $1, $2 for regex groups)' });
    form.appendChild(replaceInput);

    // Is regex
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Use Regex' }));
    const regexRow = PE.el('div', { class: 'form-checkbox-row' });
    const regexCb = PE.el('input', { type: 'checkbox' });
    if (rule.is_regex) regexCb.checked = true;
    regexRow.appendChild(regexCb);
    regexRow.appendChild(PE.el('span', { text: 'Treat match pattern as regular expression' }));
    form.appendChild(regexRow);

    // Scope pattern
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Scope Pattern' }));
    const scopeInput = PE.el('input', { class: 'input', type: 'text', value: rule.scope_pattern || '', placeholder: 'Optional: only apply to matching URLs (regex)' });
    form.appendChild(scopeInput);

    // Test area
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Quick Test' }));
    const testRow = PE.el('div', { class: 'mr-test-area' });
    const testInput = PE.el('input', { class: 'input', type: 'text', placeholder: 'Test string...', style: { flex: '1' } });
    const testResult = PE.el('div', { class: 'mr-test-result' });
    const testBtn = PE.el('button', { class: 'btn btn-xs', text: 'Test' });

    testBtn.addEventListener('click', () => {
      const pattern = matchInput.value;
      const replacement = replaceInput.value;
      const isRegex = regexCb.checked;
      const testVal = testInput.value;

      if (!pattern || !testVal) {
        testResult.textContent = 'Enter pattern and test string';
        return;
      }

      try {
        let result;
        if (isRegex) {
          const re = new RegExp(pattern, 'g');
          result = testVal.replace(re, replacement);
        } else {
          result = testVal.split(pattern).join(replacement);
        }

        const matched = result !== testVal;
        testResult.innerHTML = matched
          ? `<span class="diff-added">Result: ${PE.utils.escapeHtml(result)}</span>`
          : '<span class="diff-unchanged">No match</span>';
      } catch (e) {
        testResult.innerHTML = `<span class="diff-removed">Error: ${PE.utils.escapeHtml(e.message)}</span>`;
      }
    });

    testRow.appendChild(testInput);
    testRow.appendChild(testBtn);
    form.appendChild(testRow);
    form.appendChild(testResult);

    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: isEdit ? 'Update Rule' : 'Add Rule' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: isEdit ? 'Edit Match & Replace Rule' : 'Add Match & Replace Rule',
      body: form,
      footer: [cancelBtn, saveBtn],
      width: '550px',
    });

    cancelBtn.addEventListener('click', () => close());
    saveBtn.addEventListener('click', async () => {
      const newRule = {
        name: nameInput.value.trim(),
        phase: phaseSelect.value,
        target: targetSelect.value,
        match_pattern: matchInput.value,
        replace: replaceInput.value,
        is_regex: regexCb.checked,
        scope_pattern: scopeInput.value.trim() || undefined,
        enabled: rule.enabled !== false,
      };

      if (!newRule.match_pattern) {
        PE.toast.warning('Match pattern is required');
        return;
      }

      if (!newRule.name) {
        newRule.name = `${newRule.phase} ${newRule.target}: ${PE.utils.truncate(newRule.match_pattern, 30)}`;
      }

      // Validate regex if applicable
      if (newRule.is_regex) {
        try {
          new RegExp(newRule.match_pattern);
        } catch (e) {
          PE.toast.error('Invalid regex: ' + e.message);
          return;
        }
      }
      if (newRule.scope_pattern) {
        try {
          new RegExp(newRule.scope_pattern);
        } catch (e) {
          PE.toast.error('Invalid scope regex: ' + e.message);
          return;
        }
      }

      try {
        if (isEdit) {
          await PE.api.put(`/api/match-replace/rules/${index}`, newRule);
        } else {
          await PE.api.post('/api/match-replace/rules', newRule);
        }
        close();
        this.refresh();
        PE.toast.success(`Rule ${isEdit ? 'updated' : 'added'}`);
      } catch (e) {
        PE.toast.error('Failed to save rule: ' + e.message);
      }
    });
  },

  async _toggleRule(index) {
    const rule = this._rules[index];
    if (!rule) return;

    const newEnabled = rule.enabled === false;
    try {
      await PE.api.patch(`/api/match-replace/rules/${index}`, { enabled: newEnabled });
      rule.enabled = newEnabled;
      this._renderRules();
      PE.toast.info(`Rule ${newEnabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle rule: ' + e.message);
    }
  },

  async _deleteRule(index) {
    const ok = await PE.modal.confirm({
      title: 'Delete Rule',
      message: `Delete rule "${this._rules[index]?.name || 'Rule ' + (index + 1)}"?`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;

    try {
      await PE.api.del(`/api/match-replace/rules/${index}`);
      this.refresh();
      PE.toast.success('Rule deleted');
    } catch (e) {
      PE.toast.error('Failed to delete rule: ' + e.message);
    }
  },

  async _duplicateRule(rule) {
    const newRule = { ...rule, name: (rule.name || 'Rule') + ' (copy)' };
    delete newRule.id;

    try {
      await PE.api.post('/api/match-replace/rules', newRule);
      this.refresh();
      PE.toast.success('Rule duplicated');
    } catch (e) {
      PE.toast.error('Failed to duplicate rule: ' + e.message);
    }
  },

  async _setAllEnabled(enabled) {
    try {
      await PE.api.post('/api/match-replace/rules/toggle-all', { enabled });
      this.refresh();
      PE.toast.info(`All rules ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to update rules: ' + e.message);
    }
  },

  _showTestPreview() {
    const body = PE.el('div', {});

    body.appendChild(PE.el('div', { text: 'Enter sample content to test all enabled rules against:', style: { marginBottom: '8px' } }));

    const textarea = PE.el('textarea', { class: 'input', rows: '6', placeholder: 'Paste sample request/response content...' });
    body.appendChild(textarea);

    const resultArea = PE.el('div', { class: 'mr-test-preview-result', style: { marginTop: '12px' } });
    body.appendChild(resultArea);

    const runBtn = PE.el('button', { class: 'btn btn-primary', text: 'Run Test' });
    runBtn.addEventListener('click', () => {
      let content = textarea.value;
      if (!content) {
        resultArea.textContent = 'Enter content to test';
        return;
      }

      const applied = [];
      for (const rule of this._rules) {
        if (rule.enabled === false) continue;

        const before = content;
        try {
          if (rule.is_regex) {
            const re = new RegExp(rule.match_pattern, 'g');
            content = content.replace(re, rule.replace || '');
          } else {
            content = content.split(rule.match_pattern).join(rule.replace || '');
          }
          if (content !== before) {
            applied.push(rule.name || rule.match_pattern);
          }
        } catch (_) {}
      }

      if (applied.length === 0) {
        resultArea.innerHTML = '<div class="diff-unchanged">No rules matched the input</div>';
      } else {
        resultArea.innerHTML = `
          <div style="margin-bottom: 8px"><strong>Rules applied:</strong> ${applied.map(n => PE.utils.escapeHtml(n)).join(', ')}</div>
          <pre class="mr-test-output">${PE.utils.escapeHtml(content)}</pre>
        `;
      }
    });

    const closeBtn = PE.el('button', { class: 'btn', text: 'Close' });

    const { close } = PE.modal.show({
      title: 'Test Match & Replace Rules',
      body,
      footer: [closeBtn, runBtn],
      width: '600px',
    });

    closeBtn.addEventListener('click', () => close());
  },
};
