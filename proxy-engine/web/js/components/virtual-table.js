/**
 * VirtualTable — DOM-recycling virtual scroll that handles 50K+ rows smoothly.
 */
class VirtualTable {
  constructor(container, { columns, rowHeight = 28, onRowClick, onRowContext, onRowDblClick, getId }) {
    this.container = container;
    this.columns = columns;
    this.rowHeight = rowHeight;
    this.onRowClick = onRowClick;
    this.onRowContext = onRowContext;
    this.onRowDblClick = onRowDblClick;
    this.getId = getId || ((row) => row.id);
    this.data = [];
    this.selectedId = null;
    this._sortCol = null;
    this._sortAsc = true;
    this._pool = [];
    this._visible = new Map();
    this._scrollTop = 0;
    this._render();
    this._bindEvents();
  }

  _render() {
    this.container.innerHTML = '';
    this.container.classList.add('virtual-table-container');

    // Header
    this.headerEl = PE.el('div', { class: 'virtual-table-header' });
    for (const col of this.columns) {
      const colEl = PE.el('div', {
        class: 'vt-col' + (col.sortable ? ' sortable' : ''),
        style: { width: col.width || 'auto', flex: col.flex || 'none' },
        text: col.label,
      });
      if (col.sortable) {
        colEl.addEventListener('click', () => this._toggleSort(col.key));
      }
      this.headerEl.appendChild(colEl);
    }
    this.container.appendChild(this.headerEl);

    // Scroll area
    this.scrollEl = PE.el('div', { style: { flex: '1', overflow: 'auto', position: 'relative' } });
    this.spacerEl = PE.el('div', { style: { position: 'relative' } });
    this.scrollEl.appendChild(this.spacerEl);
    this.container.appendChild(this.scrollEl);
  }

  _bindEvents() {
    this.scrollEl.addEventListener('scroll', PE.utils.throttle(() => this._onScroll(), 16));
  }

  _toggleSort(key) {
    if (this._sortCol === key) this._sortAsc = !this._sortAsc;
    else { this._sortCol = key; this._sortAsc = true; }
    this._applySort();
    this._onScroll();

    // Update header arrows
    for (const colEl of this.headerEl.children) {
      const arrow = colEl.querySelector('.sort-arrow');
      if (arrow) arrow.remove();
    }
    const idx = this.columns.findIndex(c => c.key === key);
    if (idx >= 0) {
      this.headerEl.children[idx].appendChild(
        PE.el('span', { class: 'sort-arrow', text: this._sortAsc ? '\u25B2' : '\u25BC' })
      );
    }
  }

  _applySort() {
    if (!this._sortCol) return;
    const key = this._sortCol;
    const asc = this._sortAsc;
    this.data.sort((a, b) => {
      let va = a[key], vb = b[key];
      if (va == null) va = '';
      if (vb == null) vb = '';
      if (typeof va === 'number' && typeof vb === 'number') return asc ? va - vb : vb - va;
      va = String(va).toLowerCase();
      vb = String(vb).toLowerCase();
      return asc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
  }

  setData(data) {
    this.data = data;
    if (this._sortCol) this._applySort();
    this.spacerEl.style.height = (this.data.length * this.rowHeight) + 'px';
    this._onScroll();
  }

  appendRow(row) {
    this.data.push(row);
    this.spacerEl.style.height = (this.data.length * this.rowHeight) + 'px';
    // Auto-scroll if near bottom
    const el = this.scrollEl;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < this.rowHeight * 3) {
      requestAnimationFrame(() => { el.scrollTop = el.scrollHeight; });
    }
    this._onScroll();
  }

  updateRow(id, updates) {
    const idx = this.data.findIndex(r => this.getId(r) === id);
    if (idx >= 0) {
      Object.assign(this.data[idx], updates);
      this._onScroll();
    }
  }

  selectRow(id) {
    this.selectedId = id;
    this._visible.forEach((el, key) => {
      el.classList.toggle('selected', key === id);
    });
  }

  getSelected() {
    return this.data.find(r => this.getId(r) === this.selectedId);
  }

  _onScroll() {
    const scrollTop = this.scrollEl.scrollTop;
    const viewHeight = this.scrollEl.clientHeight;
    const startIdx = Math.max(0, Math.floor(scrollTop / this.rowHeight) - 5);
    const endIdx = Math.min(this.data.length, Math.ceil((scrollTop + viewHeight) / this.rowHeight) + 5);

    const visibleIds = new Set();
    for (let i = startIdx; i < endIdx; i++) {
      const row = this.data[i];
      const id = this.getId(row);
      visibleIds.add(id);

      let el = this._visible.get(id);
      if (!el) {
        el = this._pool.pop() || this._createRowEl();
        this._visible.set(id, el);
        this.spacerEl.appendChild(el);
      }
      this._updateRowEl(el, row, i);
    }

    // Recycle rows no longer visible
    for (const [id, el] of this._visible) {
      if (!visibleIds.has(id)) {
        this._visible.delete(id);
        el.remove();
        if (this._pool.length < 50) this._pool.push(el);
      }
    }
  }

  _createRowEl() {
    const row = PE.el('div', { class: 'virtual-table-row' });
    for (const col of this.columns) {
      row.appendChild(PE.el('div', {
        class: 'vt-cell',
        style: { width: col.width || 'auto', flex: col.flex || 'none' },
        dataset: { col: col.key },
      }));
    }
    row.addEventListener('click', (e) => {
      const id = row.dataset.rowId;
      this.selectRow(id);
      this.onRowClick?.(this.data.find(r => this.getId(r) === id), e);
    });
    row.addEventListener('dblclick', (e) => {
      const id = row.dataset.rowId;
      this.onRowDblClick?.(this.data.find(r => this.getId(r) === id), e);
    });
    row.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const id = row.dataset.rowId;
      this.selectRow(id);
      this.onRowContext?.(this.data.find(r => this.getId(r) === id), e);
    });
    return row;
  }

  _updateRowEl(el, row, index) {
    const id = this.getId(row);
    el.dataset.rowId = id;
    el.style.position = 'absolute';
    el.style.top = (index * this.rowHeight) + 'px';
    el.style.left = '0';
    el.style.right = '0';
    el.style.height = this.rowHeight + 'px';
    el.classList.toggle('selected', id === this.selectedId);

    // Highlight color
    el.className = 'virtual-table-row';
    if (row.highlight) el.classList.add(`hl-${row.highlight}`);
    if (id === this.selectedId) el.classList.add('selected');

    const cells = el.children;
    for (let i = 0; i < this.columns.length; i++) {
      const col = this.columns[i];
      const cell = cells[i];
      if (col.render) {
        cell.innerHTML = col.render(row[col.key], row);
      } else {
        cell.textContent = row[col.key] ?? '';
      }
    }
  }

  clear() {
    this.data = [];
    this._visible.forEach((el) => el.remove());
    this._visible.clear();
    this._pool = [];
    this.spacerEl.style.height = '0px';
    this.selectedId = null;
  }

  getVisibleCount() { return this._visible.size; }
  getTotalCount() { return this.data.length; }
}

PE.VirtualTable = VirtualTable;
