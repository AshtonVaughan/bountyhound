/**
 * Keyboard — Shortcut manager with ? cheat sheet overlay.
 */
PE.keyboard = {
  _bindings: [],
  _overlay: null,

  init() {
    document.addEventListener('keydown', (e) => this._handle(e));

    // Default shortcuts
    this.bind('?', 'Show keyboard shortcuts', () => this.toggleHelp());
    this.bind('Ctrl+k', 'Global search', () => PE.searchBar.open());
    this.bind('Escape', 'Close overlay', () => {
      PE.searchBar.close();
      PE.contextMenu.hide();
      PE.modal.close();
      this.hideHelp();
    });

    // Tab navigation: Ctrl+1 through Ctrl+9
    for (let i = 1; i <= 9; i++) {
      this.bind(`Ctrl+${i}`, `Switch to tab ${i}`, () => PE.bus.emit('tab:switch', i - 1));
    }

    // Panel-specific
    this.bind('Ctrl+Shift+r', 'Send to Repeater', () => PE.bus.emit('action:sendToRepeater'));
    this.bind('Ctrl+Shift+i', 'Send to Intruder', () => PE.bus.emit('action:sendToIntruder'));
    this.bind('Ctrl+Shift+s', 'Scan selected flow', () => PE.bus.emit('action:scanFlow'));
    this.bind('Ctrl+l', 'Clear flows', () => PE.bus.emit('action:clearFlows'));
    this.bind('Ctrl+f', 'Filter flows', () => PE.bus.emit('action:focusFilter'));
  },

  bind(keys, description, handler, { panel } = {}) {
    this._bindings.push({ keys, description, handler, panel });
  },

  _handle(e) {
    // Don't intercept when typing in inputs
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName) && e.key !== 'Escape') return;

    const key = this._normalizeKey(e);
    for (const binding of this._bindings) {
      if (binding.keys === key) {
        if (binding.panel && PE.state.activePanel !== binding.panel) continue;
        e.preventDefault();
        binding.handler();
        return;
      }
    }
  },

  _normalizeKey(e) {
    const parts = [];
    if (e.ctrlKey || e.metaKey) parts.push('Ctrl');
    if (e.shiftKey) parts.push('Shift');
    if (e.altKey) parts.push('Alt');
    let key = e.key;
    if (key === ' ') key = 'Space';
    if (key.length === 1) key = key.toLowerCase();
    parts.push(key);
    return parts.join('+');
  },

  toggleHelp() {
    if (this._overlay?.classList.contains('active')) this.hideHelp();
    else this.showHelp();
  },

  showHelp() {
    if (!this._overlay) {
      this._overlay = PE.el('div', { class: 'shortcuts-overlay' });
      this._overlay.addEventListener('click', (e) => { if (e.target === this._overlay) this.hideHelp(); });
      document.body.appendChild(this._overlay);
    }

    const groups = {};
    for (const b of this._bindings) {
      if (b.keys === '?') continue;
      const group = b.panel || 'Global';
      (groups[group] ||= []).push(b);
    }

    const panel = PE.el('div', { class: 'shortcuts-panel' });
    panel.appendChild(PE.el('h3', { text: 'Keyboard Shortcuts' }));

    for (const [name, bindings] of Object.entries(groups)) {
      const g = PE.el('div', { class: 'shortcut-group' });
      g.appendChild(PE.el('h4', { text: name }));
      for (const b of bindings) {
        const row = PE.el('div', { class: 'shortcut-row' });
        row.appendChild(PE.el('span', { text: b.description }));
        const keys = PE.el('span');
        b.keys.split('+').forEach((k, i) => {
          if (i > 0) keys.appendChild(document.createTextNode(' + '));
          keys.appendChild(PE.el('kbd', { text: k }));
        });
        row.appendChild(keys);
        g.appendChild(row);
      }
      panel.appendChild(g);
    }

    this._overlay.innerHTML = '';
    this._overlay.appendChild(panel);
    this._overlay.classList.add('active');
  },

  hideHelp() {
    this._overlay?.classList.remove('active');
  },
};
