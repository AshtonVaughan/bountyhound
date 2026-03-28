/**
 * TabManager — Tab switching, badges for new findings, Ctrl+1-9.
 */
PE.tabManager = {
  _tabs: [],
  _panels: {},

  init(tabConfig) {
    this._tabs = tabConfig;
    const tabbar = PE.$('.tabbar');
    const mainContent = PE.$('.main-content');
    if (!tabbar || !mainContent) return;

    tabbar.innerHTML = '';
    for (const tab of this._tabs) {
      const el = PE.el('div', { class: 'tab', dataset: { panel: tab.id } });
      el.appendChild(PE.el('span', { text: tab.label }));
      if (tab.badge) {
        el.appendChild(PE.el('span', { class: 'badge', dataset: { badgeFor: tab.id }, text: '0', style: { display: 'none' } }));
      }
      el.addEventListener('click', () => this.switchTo(tab.id));
      tabbar.appendChild(el);
    }

    // Panels
    for (const tab of this._tabs) {
      let panel = mainContent.querySelector(`#panel-${tab.id}`);
      if (!panel) {
        panel = PE.el('div', { id: `panel-${tab.id}`, class: 'panel' });
        mainContent.appendChild(panel);
      }
      this._panels[tab.id] = panel;
    }

    // Listen for tab switch events
    PE.bus.on('tab:switch', (idx) => {
      if (idx >= 0 && idx < this._tabs.length) {
        this.switchTo(this._tabs[idx].id);
      }
    });

    // Activate initial tab
    const saved = PE.getSetting('activeTab', 'dashboard');
    this.switchTo(this._tabs.find(t => t.id === saved) ? saved : this._tabs[0].id);
  },

  switchTo(id) {
    PE.state.activePanel = id;
    PE.saveSetting('activeTab', id);

    // Update tab classes
    PE.$$('.tabbar .tab').forEach(el => {
      el.classList.toggle('active', el.dataset.panel === id);
    });

    // Update panel visibility
    for (const [pid, panel] of Object.entries(this._panels)) {
      panel.classList.toggle('active', pid === id);
    }

    // Clear badge for this tab
    this.setBadge(id, 0);

    PE.bus.emit('panel:activated', id);
  },

  setBadge(tabId, count) {
    const badge = PE.$(`[data-badge-for="${tabId}"]`);
    if (!badge) return;
    if (count > 0 && PE.state.activePanel !== tabId) {
      badge.textContent = count > 99 ? '99+' : String(count);
      badge.style.display = '';
    } else {
      badge.style.display = 'none';
    }
  },

  incrementBadge(tabId) {
    const badge = PE.$(`[data-badge-for="${tabId}"]`);
    if (!badge || PE.state.activePanel === tabId) return;
    const current = parseInt(badge.textContent) || 0;
    this.setBadge(tabId, current + 1);
  },

  getPanel(id) { return this._panels[id]; },
};
