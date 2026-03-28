/**
 * SearchBar — Ctrl+K global search overlay with result grouping.
 */
PE.searchBar = {
  _overlay: null,
  _input: null,
  _results: null,
  _selectedIdx: -1,
  _items: [],

  init() {
    this._overlay = PE.el('div', { class: 'search-overlay' });
    const box = PE.el('div', { class: 'search-box' });
    this._input = PE.el('input', { type: 'text', placeholder: 'Search flows, findings, endpoints... (Ctrl+K)' });
    this._results = PE.el('div', { class: 'search-results' });
    box.appendChild(this._input);
    box.appendChild(this._results);
    this._overlay.appendChild(box);
    document.body.appendChild(this._overlay);

    this._overlay.addEventListener('click', (e) => { if (e.target === this._overlay) this.close(); });
    this._input.addEventListener('input', PE.utils.debounce(() => this._search(), 200));
    this._input.addEventListener('keydown', (e) => this._onKey(e));
  },

  open() {
    if (!this._overlay) this.init();
    this._overlay.classList.add('active');
    this._input.value = '';
    this._results.innerHTML = '';
    this._input.focus();
  },

  close() {
    this._overlay?.classList.remove('active');
  },

  async _search() {
    const q = this._input.value.trim();
    if (!q) { this._results.innerHTML = ''; this._items = []; return; }

    try {
      const data = await PE.api.get('/api/search', { q, scope: 'all', limit: 20 });
      this._items = data.results || [];
      this._selectedIdx = -1;
      this._renderResults();
    } catch (e) {
      // Fallback: search flows only
      try {
        const flows = await PE.api.get('/api/flows', { search: q, limit: 15 });
        this._items = flows.map(f => ({ type: 'flow', id: f.id, title: `${f.method} ${f.url}`, subtitle: `${f.status_code || 'pending'} - ${f.host}` }));
        this._selectedIdx = -1;
        this._renderResults();
      } catch (_) {}
    }
  },

  _renderResults() {
    this._results.innerHTML = '';
    if (!this._items.length) {
      this._results.innerHTML = '<div style="padding:12px;color:var(--text-dim)">No results</div>';
      return;
    }

    this._items.forEach((item, i) => {
      const el = PE.el('div', { class: 'search-result-item' + (i === this._selectedIdx ? ' active' : '') });
      el.appendChild(PE.el('span', { class: 'type-badge', text: item.type || 'flow' }));
      el.appendChild(PE.el('span', { text: item.title || '' }));
      if (item.subtitle) {
        el.appendChild(PE.el('span', { style: { color: 'var(--text-dim)', marginLeft: 'auto', fontSize: '11px' }, text: item.subtitle }));
      }
      el.addEventListener('click', () => this._select(item));
      this._results.appendChild(el);
    });
  },

  _onKey(e) {
    if (e.key === 'Escape') { this.close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); this._selectedIdx = Math.min(this._selectedIdx + 1, this._items.length - 1); this._renderResults(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); this._selectedIdx = Math.max(this._selectedIdx - 1, 0); this._renderResults(); }
    if (e.key === 'Enter' && this._selectedIdx >= 0) { this._select(this._items[this._selectedIdx]); }
  },

  _select(item) {
    this.close();
    if (item.type === 'flow') PE.bus.emit('navigate:flow', item.id);
    else if (item.type === 'finding') PE.bus.emit('navigate:finding', item);
    else if (item.type === 'passive') PE.bus.emit('navigate:passive', item);
  },
};
