/**
 * Sitemap Panel — Tree visualization of hosts and paths from proxy flows.
 */
PE.panels = PE.panels || {};

PE.panels.sitemap = {
  _container: null,
  _els: {},
  _tree: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('sitemap-panel');

    // ── Toolbar ───────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar', style: { display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 12px', borderBottom: '1px solid var(--border)' } });

    const refreshBtn = PE.el('button', { class: 'btn btn-sm', text: 'Refresh' });
    refreshBtn.addEventListener('click', () => this.refresh());
    toolbar.appendChild(refreshBtn);

    const expandBtn = PE.el('button', { class: 'btn btn-sm', text: 'Expand All' });
    expandBtn.addEventListener('click', () => this._expandAll());
    toolbar.appendChild(expandBtn);

    const collapseBtn = PE.el('button', { class: 'btn btn-sm', text: 'Collapse All' });
    collapseBtn.addEventListener('click', () => this._collapseAll());
    toolbar.appendChild(collapseBtn);

    this._els.filterInput = PE.el('input', {
      type: 'text',
      class: 'input',
      placeholder: 'Filter paths...',
      style: { marginLeft: 'auto', width: '200px', fontSize: '12px' },
    });
    this._els.filterInput.addEventListener('input', PE.utils.debounce(() => this._applyFilter(), 300));
    toolbar.appendChild(this._els.filterInput);

    container.appendChild(toolbar);

    // ── Tree Container ────────────────────────────────────────────────────
    this._els.treeContainer = PE.el('div', {
      class: 'sitemap-tree',
      style: { flex: '1', overflow: 'auto', padding: '4px' },
    });
    container.appendChild(this._els.treeContainer);

    // ── TreeView instance ─────────────────────────────────────────────────
    this._tree = new PE.TreeView(this._els.treeContainer, {
      onSelect: (node) => this._onNodeSelect(node),
      onContext: (node, e) => this._onNodeContext(node, e),
    });

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'sitemap') this.refresh();
    });

    PE.bus.on('flow:new', PE.utils.debounce(() => {
      if (PE.state.activePanel === 'sitemap') this.refresh();
    }, 3000));

    this.refresh();
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/sitemap');
      this._sitemapData = data;
      this._renderTree(data);
    } catch (e) {
      console.error('[sitemap] refresh failed:', e);
      this._els.treeContainer.innerHTML = '';
      this._els.treeContainer.appendChild(PE.el('div', { class: 'empty-state', style: { padding: '40px' } },
        PE.el('div', { class: 'title', text: 'No sitemap data' }),
        PE.el('div', { text: 'Browse some sites through the proxy to populate the sitemap' })
      ));
    }
  },

  _renderTree(data) {
    // data may be a tree object or an array of hosts
    let rootData;

    if (Array.isArray(data)) {
      // Array of host objects — build a root node
      rootData = {
        name: 'Sitemap',
        path: '/',
        children: {},
      };
      data.forEach(host => {
        rootData.children[host.host || host.name] = this._hostToNode(host);
      });
    } else if (data && data.children) {
      rootData = data;
    } else if (data && data.hosts) {
      rootData = {
        name: 'Sitemap',
        path: '/',
        children: {},
      };
      (data.hosts || []).forEach(host => {
        rootData.children[host.host || host.name] = this._hostToNode(host);
      });
    } else {
      this._els.treeContainer.innerHTML = '';
      this._els.treeContainer.appendChild(PE.el('div', { class: 'empty-state', style: { padding: '40px' } },
        PE.el('div', { class: 'title', text: 'No sitemap data available' })
      ));
      return;
    }

    this._tree.render(rootData);
  },

  _hostToNode(host) {
    const node = {
      name: host.host || host.name,
      path: host.host || host.name,
      methods: host.methods || [],
      flow_count: host.flow_count || host.count || 0,
      children: {},
      _isHost: true,
    };

    if (host.paths) {
      this._buildPathTree(node, host.paths);
    } else if (host.children) {
      node.children = host.children;
    }

    return node;
  },

  _buildPathTree(hostNode, paths) {
    // paths is an array of { path, methods, flow_count } or similar
    if (!Array.isArray(paths)) return;

    paths.forEach(p => {
      const pathStr = p.path || p.name || '/';
      const segments = pathStr.split('/').filter(Boolean);
      let current = hostNode;

      segments.forEach((seg, i) => {
        if (!current.children[seg]) {
          current.children[seg] = {
            name: seg,
            path: '/' + segments.slice(0, i + 1).join('/'),
            children: {},
          };
        }
        current = current.children[seg];
      });

      // Apply methods and count to the leaf
      current.methods = p.methods || [];
      current.flow_count = (current.flow_count || 0) + (p.flow_count || p.count || 0);
    });
  },

  _onNodeSelect(node) {
    // Filter proxy flows to show only flows matching this path
    if (node._isHost) {
      PE.bus.emit('filter:host', node.name);
    } else {
      PE.bus.emit('filter:path', { host: this._getHostFromNode(node), path: node.path });
    }
  },

  _getHostFromNode(node) {
    // Walk up to find the host — stored in the path for host nodes
    // For simplicity, use the path prefix
    if (node._isHost) return node.name;
    return node.path ? node.path.split('/')[0] || '' : '';
  },

  _onNodeContext(node, e) {
    const items = [];

    if (node._isHost) {
      items.push({
        label: 'Add to Scope',
        action: () => {
          PE.api.post('/api/scope/include', { pattern: node.name.replace(/\./g, '\\.'), target: 'host' })
            .then(() => PE.toast.success(`${node.name} added to scope`))
            .catch(err => PE.toast.error('Failed: ' + err.message));
        },
      });
      items.push({
        label: 'Exclude from Scope',
        action: () => {
          PE.api.post('/api/scope/exclude', { pattern: node.name.replace(/\./g, '\\.'), target: 'host' })
            .then(() => PE.toast.success(`${node.name} excluded from scope`))
            .catch(err => PE.toast.error('Failed: ' + err.message));
        },
      });
      items.push('separator');
      items.push({
        label: 'Start Crawl',
        action: () => PE.bus.emit('crawler:start', { url: `https://${node.name}/` }),
      });
      items.push({
        label: 'Start Directory Scan',
        action: () => PE.bus.emit('discovery:start', { url: `https://${node.name}/` }),
      });
    } else {
      items.push({
        label: 'Filter Flows',
        action: () => this._onNodeSelect(node),
      });
      items.push({
        label: 'Copy Path',
        action: () => PE.utils.copyToClipboard(node.path),
      });
    }

    items.push('separator');
    items.push({
      label: 'Copy URL',
      action: () => {
        const host = node._isHost ? node.name : this._getHostFromNode(node);
        const path = node._isHost ? '/' : node.path;
        PE.utils.copyToClipboard(`https://${host}${path}`);
      },
    });

    PE.contextMenu.show(e.clientX, e.clientY, items);
  },

  _expandAll() {
    const nodes = this._els.treeContainer.querySelectorAll('.tree-node-children');
    nodes.forEach(n => { n.style.display = ''; });
    const toggles = this._els.treeContainer.querySelectorAll('.tree-node-toggle');
    toggles.forEach(t => { if (t.textContent === '\u25B6') t.textContent = '\u25BC'; });
  },

  _collapseAll() {
    const nodes = this._els.treeContainer.querySelectorAll('.tree-node-children');
    nodes.forEach((n, i) => { if (i > 0) n.style.display = 'none'; });
    const toggles = this._els.treeContainer.querySelectorAll('.tree-node-toggle');
    toggles.forEach(t => { if (t.textContent === '\u25BC') t.textContent = '\u25B6'; });
  },

  _applyFilter() {
    const filter = this._els.filterInput.value.toLowerCase().trim();
    const headers = this._els.treeContainer.querySelectorAll('.tree-node-header');

    if (!filter) {
      headers.forEach(h => { h.closest('.tree-node').style.display = ''; });
      return;
    }

    headers.forEach(h => {
      const text = h.textContent.toLowerCase();
      const node = h.closest('.tree-node');
      const matches = text.includes(filter);
      node.style.display = matches ? '' : 'none';

      // Show parent nodes if a child matches
      if (matches) {
        let parent = node.parentElement?.closest('.tree-node');
        while (parent) {
          parent.style.display = '';
          const childrenEl = parent.querySelector('.tree-node-children');
          if (childrenEl) childrenEl.style.display = '';
          parent = parent.parentElement?.closest('.tree-node');
        }
      }
    });
  },
};
