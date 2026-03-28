/**
 * SplitPane — Draggable horizontal/vertical split with ratio persisted to localStorage.
 */
class SplitPane {
  constructor(container, { direction = 'vertical', initialRatio = 0.5, storageKey, minSize = 60 }) {
    this.container = container;
    this.direction = direction;
    this.ratio = PE.getSetting(`split-${storageKey}`, initialRatio);
    this.storageKey = storageKey;
    this.minSize = minSize;
    this._dragging = false;
    this._render();
    this._bindEvents();
    this._applyRatio();
  }

  _render() {
    this.container.classList.add('split-container', this.direction);
    this.pane1 = this.container.children[0];
    this.pane2 = this.container.children[2] || this.container.children[1];
    this.handle = this.container.querySelector('.split-handle');

    if (!this.handle) {
      // Auto-create structure
      const children = [...this.container.children];
      this.container.innerHTML = '';
      this.pane1 = children[0] || PE.el('div', { class: 'split-pane' });
      this.pane2 = children[1] || PE.el('div', { class: 'split-pane' });
      this.handle = PE.el('div', { class: 'split-handle' });
      this.pane1.classList.add('split-pane');
      this.pane2.classList.add('split-pane');
      this.container.appendChild(this.pane1);
      this.container.appendChild(this.handle);
      this.container.appendChild(this.pane2);
    }
  }

  _bindEvents() {
    this.handle.addEventListener('mousedown', (e) => {
      e.preventDefault();
      this._dragging = true;
      this.handle.classList.add('dragging');
      document.body.style.cursor = this.direction === 'horizontal' ? 'col-resize' : 'row-resize';
      document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!this._dragging) return;
      const rect = this.container.getBoundingClientRect();
      if (this.direction === 'horizontal') {
        const x = e.clientX - rect.left;
        this.ratio = Math.max(this.minSize / rect.width, Math.min(1 - this.minSize / rect.width, x / rect.width));
      } else {
        const y = e.clientY - rect.top;
        this.ratio = Math.max(this.minSize / rect.height, Math.min(1 - this.minSize / rect.height, y / rect.height));
      }
      this._applyRatio();
    });

    document.addEventListener('mouseup', () => {
      if (!this._dragging) return;
      this._dragging = false;
      this.handle.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      if (this.storageKey) PE.saveSetting(`split-${this.storageKey}`, this.ratio);
    });
  }

  _applyRatio() {
    const pct1 = (this.ratio * 100).toFixed(2) + '%';
    const pct2 = ((1 - this.ratio) * 100).toFixed(2) + '%';
    if (this.direction === 'horizontal') {
      this.pane1.style.width = pct1;
      this.pane2.style.width = pct2;
      this.pane1.style.height = '100%';
      this.pane2.style.height = '100%';
    } else {
      this.pane1.style.height = pct1;
      this.pane2.style.height = pct2;
      this.pane1.style.width = '100%';
      this.pane2.style.width = '100%';
    }
  }

  setRatio(r) {
    this.ratio = r;
    this._applyRatio();
    if (this.storageKey) PE.saveSetting(`split-${this.storageKey}`, this.ratio);
  }
}

PE.SplitPane = SplitPane;
