/**
 * ContextMenu — Right-click menus with keyboard navigation.
 */
PE.contextMenu = {
  _el: null,
  _onClose: null,

  show(x, y, items) {
    this.hide();
    const menu = PE.el('div', { class: 'context-menu' });

    for (const item of items) {
      if (item === 'separator' || item.separator) {
        menu.appendChild(PE.el('div', { class: 'context-menu-separator' }));
        continue;
      }
      const el = PE.el('div', {
        class: 'context-menu-item' + (item.disabled ? ' disabled' : ''),
      });
      if (item.icon) el.appendChild(PE.el('span', { text: item.icon }));
      el.appendChild(PE.el('span', { text: item.label }));
      if (item.shortcut) el.appendChild(PE.el('span', { class: 'shortcut', text: item.shortcut }));
      if (!item.disabled) {
        el.addEventListener('click', () => { this.hide(); item.action?.(); });
      }
      menu.appendChild(el);
    }

    // Position within viewport
    document.body.appendChild(menu);
    const rect = menu.getBoundingClientRect();
    if (x + rect.width > window.innerWidth) x = window.innerWidth - rect.width - 4;
    if (y + rect.height > window.innerHeight) y = window.innerHeight - rect.height - 4;
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    this._el = menu;

    // Close on click outside
    this._onClose = (e) => { if (!menu.contains(e.target)) this.hide(); };
    setTimeout(() => document.addEventListener('click', this._onClose), 0);
    document.addEventListener('keydown', this._escHandler);
  },

  _escHandler(e) {
    if (e.key === 'Escape') PE.contextMenu.hide();
  },

  hide() {
    if (this._el) { this._el.remove(); this._el = null; }
    document.removeEventListener('click', this._onClose);
    document.removeEventListener('keydown', this._escHandler);
  },

  flowMenu(flow, x, y) {
    if (!flow) return;
    this.show(x, y, [
      { label: 'Send to Repeater', icon: '\u21A9', action: () => PE.bus.emit('flow:sendToRepeater', flow) },
      { label: 'Send to Intruder', icon: '\u2699', action: () => PE.bus.emit('flow:sendToIntruder', flow) },
      { label: 'Scan Flow', icon: '\u26A1', action: () => PE.bus.emit('flow:scan', flow) },
      'separator',
      { label: 'Copy URL', action: () => PE.utils.copyToClipboard(flow.url) },
      { label: 'Copy as cURL', shortcut: 'Ctrl+C', action: () => {
        PE.api.getText(`/api/export/${flow.id}?format=curl`).then(t => PE.utils.copyToClipboard(t));
      }},
      { label: 'Copy as Python', action: () => {
        PE.api.getText(`/api/export/${flow.id}?format=python`).then(t => PE.utils.copyToClipboard(t));
      }},
      'separator',
      { label: 'Highlight Red', action: () => PE.api.patch(`/api/flows/${flow.id}/notes`, { highlight: 'red' }).then(() => PE.bus.emit('flow:updated', flow.id)) },
      { label: 'Highlight Green', action: () => PE.api.patch(`/api/flows/${flow.id}/notes`, { highlight: 'green' }).then(() => PE.bus.emit('flow:updated', flow.id)) },
      { label: 'Highlight Yellow', action: () => PE.api.patch(`/api/flows/${flow.id}/notes`, { highlight: 'yellow' }).then(() => PE.bus.emit('flow:updated', flow.id)) },
      { label: 'Clear Highlight', action: () => PE.api.patch(`/api/flows/${flow.id}/notes`, { highlight: '' }).then(() => PE.bus.emit('flow:updated', flow.id)) },
      'separator',
      { label: 'Add to Scope', action: () => {
        PE.api.post('/api/scope/include', { pattern: flow.host.replace(/\./g, '\\.'), target: 'host' });
      }},
      { label: 'Delete Flow', icon: '\u2716', action: () => PE.bus.emit('flow:delete', flow) },
    ]);
  },
};
