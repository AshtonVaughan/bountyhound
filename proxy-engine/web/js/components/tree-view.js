/**
 * TreeView — Collapsible tree for sitemap / GraphQL schema.
 */
class TreeView {
  constructor(container, { onSelect, onContext } = {}) {
    this.container = container;
    this.onSelect = onSelect;
    this.onContext = onContext;
    this.selectedPath = null;
  }

  render(rootData) {
    this.container.innerHTML = '';
    this._renderNode(this.container, rootData, 0);
  }

  _renderNode(parent, node, depth) {
    const hasChildren = node.children && Object.keys(node.children).length > 0;
    const nodeEl = PE.el('div', { class: 'tree-node' });
    const header = PE.el('div', { class: 'tree-node-header', style: { paddingLeft: (depth * 8 + 4) + 'px' } });

    const toggle = PE.el('span', { class: 'tree-node-toggle', text: hasChildren ? '\u25B6' : '\u00A0' });
    header.appendChild(toggle);
    header.appendChild(PE.el('span', { text: node.name || '/' }));

    if (node.methods?.length) {
      const methods = PE.el('span', { style: { marginLeft: '6px', fontSize: '10px', color: 'var(--text-muted)' } });
      node.methods.forEach(m => {
        methods.appendChild(PE.el('span', { class: `method-${m}`, text: m, style: { marginRight: '4px' } }));
      });
      header.appendChild(methods);
    }

    if (node.flow_count) {
      header.appendChild(PE.el('span', { style: { marginLeft: 'auto', fontSize: '10px', color: 'var(--text-muted)' }, text: `(${node.flow_count})` }));
    }

    header.addEventListener('click', () => {
      this.selectedPath = node.path;
      this.container.querySelectorAll('.tree-node-header').forEach(h => h.classList.remove('selected'));
      header.classList.add('selected');
      if (hasChildren) {
        const expanded = childrenEl.style.display !== 'none';
        childrenEl.style.display = expanded ? 'none' : '';
        toggle.textContent = expanded ? '\u25B6' : '\u25BC';
      }
      this.onSelect?.(node);
    });

    if (this.onContext) {
      header.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        this.onContext(node, e);
      });
    }

    nodeEl.appendChild(header);

    const childrenEl = PE.el('div', { class: 'tree-node-children', style: { display: depth > 1 ? 'none' : '' } });
    if (hasChildren) {
      if (depth <= 1) toggle.textContent = '\u25BC';
      const sorted = Object.entries(node.children).sort(([a], [b]) => a.localeCompare(b));
      for (const [, child] of sorted) {
        this._renderNode(childrenEl, child, depth + 1);
      }
    }
    nodeEl.appendChild(childrenEl);
    parent.appendChild(nodeEl);
  }
}

PE.TreeView = TreeView;
