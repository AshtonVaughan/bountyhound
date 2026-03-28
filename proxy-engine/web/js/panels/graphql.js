/**
 * GraphQL Panel — Schema introspection, query builder, executor, and vuln checks.
 */
PE.panels = PE.panels || {};

PE.panels.graphql = {
  _container: null,
  _els: {},
  _schemaTree: null,
  _schema: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('graphql-panel');

    // ── Horizontal split: schema left, query+response right ───────────────
    const splitWrap = PE.el('div', { class: 'split-container', style: { display: 'flex', height: '100%' } });

    const leftPane = PE.el('div', { class: 'split-pane' });
    const rightPane = PE.el('div', { class: 'split-pane', style: { display: 'flex', flexDirection: 'column' } });

    // ── Left: Introspection + Schema Tree ─────────────────────────────────
    const introHeader = PE.el('div', { style: { padding: '8px 12px', borderBottom: '1px solid var(--border)' } });
    introHeader.appendChild(PE.el('h3', { text: 'GraphQL Schema', style: { marginBottom: '6px', fontSize: '14px' } }));

    const introRow = PE.el('div', { style: { display: 'flex', gap: '6px' } });
    this._els.targetInput = PE.el('input', {
      type: 'text', class: 'input', placeholder: 'https://api.example.com/graphql',
      style: { flex: '1', fontSize: '12px' },
    });
    introRow.appendChild(this._els.targetInput);

    const introspectBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Introspect' });
    introspectBtn.addEventListener('click', () => this._introspect());
    introRow.appendChild(introspectBtn);
    introHeader.appendChild(introRow);

    leftPane.appendChild(introHeader);

    this._els.schemaContainer = PE.el('div', {
      class: 'graphql-schema-tree',
      style: { flex: '1', overflow: 'auto', padding: '4px' },
    });
    leftPane.appendChild(this._els.schemaContainer);

    // Initialize TreeView
    this._schemaTree = new PE.TreeView(this._els.schemaContainer, {
      onSelect: (node) => this._onSchemaNodeSelect(node),
    });

    // Empty state
    this._els.schemaEmpty = PE.el('div', { class: 'empty-state', style: { padding: '30px', textAlign: 'center' } },
      PE.el('div', { class: 'title', text: 'No schema loaded' }),
      PE.el('div', { text: 'Enter a GraphQL endpoint and click Introspect' })
    );
    this._els.schemaContainer.appendChild(this._els.schemaEmpty);

    // ── Right Top: Query Builder ──────────────────────────────────────────
    const querySection = PE.el('div', { style: { flex: '1', display: 'flex', flexDirection: 'column', borderBottom: '1px solid var(--border)' } });

    const queryHeader = PE.el('div', {
      style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', borderBottom: '1px solid var(--border)' },
    });
    queryHeader.appendChild(PE.el('h4', { text: 'Query', style: { fontSize: '13px' } }));

    const executeBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Execute' });
    executeBtn.addEventListener('click', () => this._executeQuery());
    queryHeader.appendChild(executeBtn);

    const prettifyBtn = PE.el('button', { class: 'btn btn-sm btn-ghost', text: 'Prettify' });
    prettifyBtn.addEventListener('click', () => this._prettifyQuery());
    queryHeader.appendChild(prettifyBtn);

    const vulnCheckBtn = PE.el('button', { class: 'btn btn-sm btn-ghost', text: 'Vuln Check', style: { marginLeft: 'auto' } });
    vulnCheckBtn.addEventListener('click', () => this._runVulnChecks());
    queryHeader.appendChild(vulnCheckBtn);

    querySection.appendChild(queryHeader);

    this._els.queryTA = PE.el('textarea', {
      class: 'input mono graphql-query-editor',
      style: {
        flex: '1', width: '100%', resize: 'none', fontFamily: 'monospace', fontSize: '12px',
        padding: '8px', border: 'none', borderRadius: '0', outline: 'none',
        background: 'var(--bg-secondary, var(--bg))',
      },
      placeholder: '{\n  __typename\n}',
    });
    querySection.appendChild(this._els.queryTA);

    // Variables input
    const varsRow = PE.el('div', { style: { padding: '4px 12px', borderTop: '1px solid var(--border)' } });
    varsRow.appendChild(PE.el('label', { text: 'Variables (JSON)', style: { fontSize: '10px', color: 'var(--text-muted)' } }));
    this._els.varsTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '40px', fontFamily: 'monospace', fontSize: '11px', resize: 'vertical', marginTop: '2px' },
      placeholder: '{}',
    });
    varsRow.appendChild(this._els.varsTA);
    querySection.appendChild(varsRow);

    rightPane.appendChild(querySection);

    // ── Right Bottom: Response Viewer ─────────────────────────────────────
    const responseSection = PE.el('div', { style: { flex: '1', display: 'flex', flexDirection: 'column' } });

    const responseHeader = PE.el('div', {
      style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', borderBottom: '1px solid var(--border)' },
    });
    responseHeader.appendChild(PE.el('h4', { text: 'Response', style: { fontSize: '13px' } }));
    this._els.responseStatus = PE.el('span', { style: { fontSize: '11px', color: 'var(--text-muted)' } });
    responseHeader.appendChild(this._els.responseStatus);

    const copyResponseBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Copy', style: { marginLeft: 'auto' } });
    copyResponseBtn.addEventListener('click', () => {
      const text = this._els.responseBody?.textContent || '';
      PE.utils.copyToClipboard(text);
    });
    responseHeader.appendChild(copyResponseBtn);

    responseSection.appendChild(responseHeader);

    this._els.responseBody = PE.el('div', {
      class: 'graphql-response',
      style: { flex: '1', overflow: 'auto', padding: '8px', fontSize: '12px' },
    });
    responseSection.appendChild(this._els.responseBody);

    rightPane.appendChild(responseSection);

    // ── Vuln Check Results ────────────────────────────────────────────────
    this._els.vulnResults = PE.el('div', {
      class: 'graphql-vuln-results',
      style: { display: 'none', borderTop: '1px solid var(--border)', padding: '8px 12px', maxHeight: '200px', overflow: 'auto' },
    });
    rightPane.appendChild(this._els.vulnResults);

    splitWrap.appendChild(leftPane);
    splitWrap.appendChild(PE.el('div', { class: 'split-handle' }));
    splitWrap.appendChild(rightPane);
    container.appendChild(splitWrap);

    new PE.SplitPane(splitWrap, { direction: 'horizontal', initialRatio: 0.35, storageKey: 'graphql-split' });

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'graphql') this._els.queryTA.focus();
    });

    // Ctrl+Enter to execute
    this._els.queryTA.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        this._executeQuery();
      }
    });
  },

  async _introspect() {
    const target = this._els.targetInput.value.trim();
    if (!target) { PE.toast.warning('Target URL is required'); return; }

    try {
      PE.toast.info('Running introspection...');
      const result = await PE.api.post('/api/graphql/introspect', { url: target });
      this._schema = result.schema || result.__schema || result;
      this._renderSchemaTree();
      PE.toast.success('Schema loaded');
    } catch (e) {
      PE.toast.error('Introspection failed: ' + e.message);
    }
  },

  _renderSchemaTree() {
    this._els.schemaEmpty.style.display = 'none';

    if (!this._schema) return;

    const types = this._schema.types || this._schema.__schema?.types || [];
    const queryType = this._schema.queryType?.name || this._schema.__schema?.queryType?.name || 'Query';
    const mutationType = this._schema.mutationType?.name || this._schema.__schema?.mutationType?.name || 'Mutation';
    const subscriptionType = this._schema.subscriptionType?.name || this._schema.__schema?.subscriptionType?.name || 'Subscription';

    // Build tree data
    const rootData = {
      name: 'Schema',
      path: '/',
      children: {},
    };

    // Organize types into categories
    const categories = {
      'Query': { name: 'Query', path: '/Query', children: {} },
      'Mutation': { name: 'Mutation', path: '/Mutation', children: {} },
      'Subscription': { name: 'Subscription', path: '/Subscription', children: {} },
      'Types': { name: 'Types', path: '/Types', children: {} },
      'Input Types': { name: 'Input Types', path: '/InputTypes', children: {} },
      'Enums': { name: 'Enums', path: '/Enums', children: {} },
    };

    types.forEach(type => {
      if (!type.name || type.name.startsWith('__')) return;

      const typeNode = this._buildTypeNode(type);

      if (type.name === queryType) {
        categories['Query'].children = typeNode.children;
      } else if (type.name === mutationType) {
        categories['Mutation'].children = typeNode.children;
      } else if (type.name === subscriptionType) {
        categories['Subscription'].children = typeNode.children;
      } else if (type.kind === 'INPUT_OBJECT') {
        categories['Input Types'].children[type.name] = typeNode;
      } else if (type.kind === 'ENUM') {
        categories['Enums'].children[type.name] = typeNode;
      } else if (type.kind === 'OBJECT' || type.kind === 'INTERFACE' || type.kind === 'UNION') {
        categories['Types'].children[type.name] = typeNode;
      }
    });

    // Only add categories that have children
    for (const [key, cat] of Object.entries(categories)) {
      if (Object.keys(cat.children).length > 0) {
        rootData.children[key] = cat;
      }
    }

    this._schemaTree.render(rootData);
  },

  _buildTypeNode(type) {
    const node = {
      name: type.name,
      path: `/${type.name}`,
      children: {},
      _type: type,
    };

    const fields = type.fields || [];
    fields.forEach(field => {
      const fieldNode = {
        name: this._fieldSignature(field),
        path: `/${type.name}/${field.name}`,
        children: {},
        _field: field,
        _parentType: type.name,
      };

      // Add arguments as children
      if (field.args && field.args.length) {
        field.args.forEach(arg => {
          fieldNode.children[arg.name] = {
            name: `${arg.name}: ${this._typeRefName(arg.type)}`,
            path: `/${type.name}/${field.name}/${arg.name}`,
            children: {},
            _arg: arg,
          };
        });
      }

      node.children[field.name] = fieldNode;
    });

    // Enum values
    if (type.enumValues) {
      type.enumValues.forEach(ev => {
        node.children[ev.name] = {
          name: ev.name,
          path: `/${type.name}/${ev.name}`,
          children: {},
        };
      });
    }

    // Input fields
    if (type.inputFields) {
      type.inputFields.forEach(f => {
        node.children[f.name] = {
          name: `${f.name}: ${this._typeRefName(f.type)}`,
          path: `/${type.name}/${f.name}`,
          children: {},
        };
      });
    }

    return node;
  },

  _fieldSignature(field) {
    const args = field.args && field.args.length
      ? `(${field.args.map(a => `${a.name}: ${this._typeRefName(a.type)}`).join(', ')})`
      : '';
    return `${field.name}${args}: ${this._typeRefName(field.type)}`;
  },

  _typeRefName(typeRef) {
    if (!typeRef) return '?';
    if (typeRef.kind === 'NON_NULL') return this._typeRefName(typeRef.ofType) + '!';
    if (typeRef.kind === 'LIST') return `[${this._typeRefName(typeRef.ofType)}]`;
    return typeRef.name || '?';
  },

  _onSchemaNodeSelect(node) {
    if (node._field && node._parentType) {
      // Insert a query for this field into the editor
      const field = node._field;
      const args = field.args && field.args.length
        ? `(${field.args.map(a => `${a.name}: ${this._defaultArgValue(a.type)}`).join(', ')})`
        : '';

      const returnType = this._typeRefName(field.type).replace(/[!\[\]]/g, '');
      const subfields = this._getSubfields(returnType);
      const subfieldStr = subfields.length ? ` {\n    ${subfields.join('\n    ')}\n  }` : '';

      const query = `{\n  ${field.name}${args}${subfieldStr}\n}`;
      this._els.queryTA.value = query;
    }
  },

  _defaultArgValue(typeRef) {
    if (!typeRef) return '""';
    if (typeRef.kind === 'NON_NULL') return this._defaultArgValue(typeRef.ofType);
    if (typeRef.kind === 'LIST') return '[]';
    const name = typeRef.name || '';
    if (name === 'String' || name === 'ID') return '""';
    if (name === 'Int' || name === 'Float') return '0';
    if (name === 'Boolean') return 'false';
    return '{}';
  },

  _getSubfields(typeName) {
    if (!this._schema) return [];
    const types = this._schema.types || this._schema.__schema?.types || [];
    const type = types.find(t => t.name === typeName);
    if (!type || !type.fields) return [];
    // Return first 5 scalar fields
    return type.fields
      .filter(f => {
        const inner = this._unwrapType(f.type);
        return ['String', 'Int', 'Float', 'Boolean', 'ID'].includes(inner);
      })
      .slice(0, 5)
      .map(f => f.name);
  },

  _unwrapType(typeRef) {
    if (!typeRef) return '';
    if (typeRef.kind === 'NON_NULL' || typeRef.kind === 'LIST') return this._unwrapType(typeRef.ofType);
    return typeRef.name || '';
  },

  async _executeQuery() {
    const query = this._els.queryTA.value.trim();
    if (!query) { PE.toast.warning('Query is empty'); return; }

    const target = this._els.targetInput.value.trim();
    if (!target) { PE.toast.warning('Target URL is required'); return; }

    let variables = {};
    const varsText = this._els.varsTA.value.trim();
    if (varsText) {
      try {
        variables = JSON.parse(varsText);
      } catch (_) {
        PE.toast.warning('Invalid JSON in variables');
        return;
      }
    }

    this._els.responseStatus.textContent = 'Executing...';
    this._els.responseBody.innerHTML = '';

    try {
      const startTime = performance.now();
      const result = await PE.api.post('/api/graphql/query', { url: target, query, variables });
      const elapsed = Math.round(performance.now() - startTime);

      this._els.responseStatus.textContent = `${elapsed}ms`;

      const responseStr = JSON.stringify(result.data || result, null, 2);
      PE.syntax.renderInto(this._els.responseBody, responseStr, 'json');

      // Check for errors in the response
      if (result.errors && result.errors.length) {
        const errEl = PE.el('div', { style: { padding: '8px', marginBottom: '8px', background: 'rgba(230,57,70,0.1)', borderRadius: '4px', border: '1px solid rgba(230,57,70,0.3)' } });
        errEl.appendChild(PE.el('strong', { text: `${result.errors.length} error(s):`, style: { color: 'var(--sev-high, #f77f00)', fontSize: '12px' } }));
        result.errors.forEach(err => {
          errEl.appendChild(PE.el('div', {
            text: err.message || JSON.stringify(err),
            style: { fontSize: '11px', marginTop: '2px', color: 'var(--text-muted)' },
          }));
        });
        this._els.responseBody.insertBefore(errEl, this._els.responseBody.firstChild);
      }
    } catch (e) {
      this._els.responseStatus.textContent = 'Error';
      this._els.responseBody.innerHTML = '';
      this._els.responseBody.appendChild(PE.el('div', {
        text: e.message,
        style: { color: 'var(--sev-high, #f77f00)', padding: '12px' },
      }));
    }
  },

  _prettifyQuery() {
    const raw = this._els.queryTA.value;
    if (!raw.trim()) return;
    // Simple indent normalization
    try {
      let depth = 0;
      const lines = raw.replace(/\s+/g, ' ').replace(/\s*{\s*/g, ' {\n').replace(/\s*}\s*/g, '\n}\n')
        .replace(/\s*,\s*/g, '\n').split('\n').filter(l => l.trim());
      const formatted = [];
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed === '}') depth = Math.max(0, depth - 1);
        formatted.push('  '.repeat(depth) + trimmed);
        if (trimmed.endsWith('{')) depth++;
      }
      this._els.queryTA.value = formatted.join('\n');
    } catch (_) {
      // Leave as-is if formatting fails
    }
  },

  async _runVulnChecks() {
    const target = this._els.targetInput.value.trim();
    if (!target) { PE.toast.warning('Target URL is required'); return; }

    this._els.vulnResults.style.display = '';
    this._els.vulnResults.innerHTML = '';
    this._els.vulnResults.appendChild(PE.el('div', { text: 'Running vulnerability checks...', style: { color: 'var(--text-muted)', fontSize: '12px', padding: '8px 0' } }));

    try {
      const result = await PE.api.post('/api/graphql/vulncheck', { url: target });
      const checks = result.checks || result.results || result || [];
      this._renderVulnResults(checks);
    } catch (e) {
      this._els.vulnResults.innerHTML = '';
      this._els.vulnResults.appendChild(PE.el('div', {
        text: 'Vulnerability check failed: ' + e.message,
        style: { color: 'var(--sev-high, #f77f00)', fontSize: '12px' },
      }));
    }
  },

  _renderVulnResults(checks) {
    this._els.vulnResults.innerHTML = '';

    if (!checks.length) {
      this._els.vulnResults.appendChild(PE.el('div', {
        text: 'No vulnerability findings.',
        style: { color: 'var(--text-muted)', fontSize: '12px', padding: '4px 0' },
      }));
      return;
    }

    this._els.vulnResults.appendChild(PE.el('h4', { text: 'Vulnerability Check Results', style: { marginBottom: '6px', fontSize: '13px' } }));

    checks.forEach(check => {
      const name = check.name || check.check || 'Unknown';
      const status = check.vulnerable ? 'VULNERABLE' : (check.status || 'SAFE');
      const severity = check.severity || (check.vulnerable ? 'high' : 'info');
      const isVuln = check.vulnerable || status === 'VULNERABLE';

      const row = PE.el('div', {
        style: {
          display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 0',
          borderBottom: '1px solid var(--border)',
        },
      });

      // Status indicator
      row.appendChild(PE.el('span', {
        text: isVuln ? '\u26A0' : '\u2713',
        style: { color: isVuln ? 'var(--sev-high, #f77f00)' : 'var(--success, #2a9d8f)', fontSize: '14px' },
      }));

      // Name
      row.appendChild(PE.el('span', { text: name, style: { flex: '1', fontSize: '12px', fontWeight: '500' } }));

      // Severity badge
      row.appendChild(PE.el('span', {
        class: `badge ${PE.utils.sevClass(severity)}`,
        text: severity.toUpperCase(),
        style: { fontSize: '10px' },
      }));

      // Status
      row.appendChild(PE.el('span', {
        text: status,
        style: { fontSize: '11px', fontWeight: '600', color: isVuln ? 'var(--sev-high, #f77f00)' : 'var(--text-muted)' },
      }));

      this._els.vulnResults.appendChild(row);

      // Details
      if (check.details || check.description) {
        this._els.vulnResults.appendChild(PE.el('div', {
          text: check.details || check.description,
          style: { fontSize: '11px', color: 'var(--text-muted)', padding: '0 0 4px 28px' },
        }));
      }
    });
  },
};
