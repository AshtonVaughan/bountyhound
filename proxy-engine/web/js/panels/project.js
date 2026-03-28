/**
 * Project Panel — Save, load, list, and delete projects.
 */
PE.panels = PE.panels || {};

PE.panels.project = {
  _container: null,
  _els: {},
  _projects: [],
  _currentProject: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('project-panel');

    const scrollWrap = PE.el('div', { style: { overflow: 'auto', height: '100%', padding: '16px', maxWidth: '600px' } });

    // ── Current Project Indicator ─────────────────────────────────────────
    this._els.currentProject = PE.el('div', {
      class: 'project-current',
      style: { padding: '12px', borderRadius: '6px', background: 'var(--bg-raised, var(--bg-secondary))', marginBottom: '16px', border: '1px solid var(--border)' },
    });
    scrollWrap.appendChild(this._els.currentProject);

    // ── Save Project Section ──────────────────────────────────────────────
    const saveSection = PE.el('div', { style: { marginBottom: '20px' } });
    saveSection.appendChild(PE.el('h3', {
      text: 'Save Project',
      style: { marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid var(--border)', fontSize: '14px' },
    }));

    const saveRow = PE.el('div', { style: { display: 'flex', gap: '8px', alignItems: 'end' } });

    const nameGroup = PE.el('div', { style: { flex: '1' } });
    nameGroup.appendChild(PE.el('label', { text: 'Project Name', style: { display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' } }));
    this._els.nameInput = PE.el('input', { type: 'text', class: 'input', placeholder: 'my-project', style: { width: '100%' } });
    nameGroup.appendChild(this._els.nameInput);
    saveRow.appendChild(nameGroup);

    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: 'Save' });
    saveBtn.addEventListener('click', () => this._saveProject());
    saveRow.appendChild(saveBtn);

    saveSection.appendChild(saveRow);

    // Auto-save indicator
    this._els.autoSaveStatus = PE.el('div', {
      style: { marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' },
    });
    saveSection.appendChild(this._els.autoSaveStatus);

    scrollWrap.appendChild(saveSection);

    // ── Saved Projects List ───────────────────────────────────────────────
    const listSection = PE.el('div');
    listSection.appendChild(PE.el('h3', {
      text: 'Saved Projects',
      style: { marginBottom: '8px', paddingBottom: '4px', borderBottom: '1px solid var(--border)', fontSize: '14px' },
    }));

    this._els.projectsList = PE.el('div', { class: 'projects-list' });
    listSection.appendChild(this._els.projectsList);

    scrollWrap.appendChild(listSection);
    container.appendChild(scrollWrap);

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'project') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const [projectsData, statusData] = await Promise.all([
        PE.api.get('/api/projects'),
        PE.api.get('/api/projects/current').catch(() => null),
      ]);
      this._projects = projectsData.projects || projectsData || [];
      this._currentProject = statusData?.name || statusData?.project || null;
      this._renderCurrentProject(statusData);
      this._renderProjectsList();
      this._renderAutoSaveStatus(statusData);
    } catch (e) {
      console.error('[project] refresh failed:', e);
    }
  },

  _renderCurrentProject(status) {
    this._els.currentProject.innerHTML = '';

    const row = PE.el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } });

    const dot = PE.el('span', {
      style: {
        width: '10px', height: '10px', borderRadius: '50%', flexShrink: '0',
        background: this._currentProject ? 'var(--success, #2a9d8f)' : 'var(--text-muted)',
      },
    });
    row.appendChild(dot);

    if (this._currentProject) {
      row.appendChild(PE.el('span', { text: 'Current Project: ', style: { fontSize: '12px', color: 'var(--text-muted)' } }));
      row.appendChild(PE.el('strong', { text: this._currentProject, style: { fontSize: '14px' } }));

      // Pre-fill the name input
      if (!this._els.nameInput.value) {
        this._els.nameInput.value = this._currentProject;
      }
    } else {
      row.appendChild(PE.el('span', { text: 'No project loaded', style: { fontSize: '12px', color: 'var(--text-muted)' } }));
    }

    this._els.currentProject.appendChild(row);

    // Stats if available
    if (status && (status.flow_count || status.finding_count)) {
      const stats = PE.el('div', { style: { display: 'flex', gap: '16px', marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' } });
      if (status.flow_count != null) stats.appendChild(PE.el('span', { text: `Flows: ${status.flow_count}` }));
      if (status.finding_count != null) stats.appendChild(PE.el('span', { text: `Findings: ${status.finding_count}` }));
      if (status.last_saved) stats.appendChild(PE.el('span', { text: `Last saved: ${PE.utils.relativeTime(status.last_saved)}` }));
      this._els.currentProject.appendChild(stats);
    }
  },

  _renderAutoSaveStatus(status) {
    if (status && status.auto_save !== undefined) {
      const enabled = status.auto_save;
      this._els.autoSaveStatus.innerHTML = '';

      const label = PE.el('label', { style: { display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' } });
      const cb = PE.el('input', { type: 'checkbox' });
      cb.checked = enabled;
      cb.addEventListener('change', async () => {
        try {
          await PE.api.patch('/api/projects/current', { auto_save: cb.checked });
          PE.toast.success(`Auto-save ${cb.checked ? 'enabled' : 'disabled'}`);
        } catch (e) {
          PE.toast.error('Failed to update auto-save: ' + e.message);
        }
      });
      label.appendChild(cb);
      label.appendChild(PE.el('span', { text: 'Auto-save enabled' }));
      this._els.autoSaveStatus.appendChild(label);

      if (status.auto_save_interval) {
        this._els.autoSaveStatus.appendChild(PE.el('span', {
          text: ` (every ${status.auto_save_interval}s)`,
          style: { marginLeft: '4px' },
        }));
      }
    } else {
      this._els.autoSaveStatus.textContent = '';
    }
  },

  _renderProjectsList() {
    this._els.projectsList.innerHTML = '';

    if (!this._projects.length) {
      this._els.projectsList.appendChild(PE.el('div', { class: 'empty-state', style: { padding: '24px', textAlign: 'center' } },
        PE.el('div', { class: 'title', text: 'No saved projects' }),
        PE.el('div', { text: 'Save your first project using the form above' })
      ));
      return;
    }

    this._projects.forEach(project => {
      const name = typeof project === 'string' ? project : (project.name || project.id);
      const isCurrent = name === this._currentProject;

      const row = PE.el('div', {
        class: 'project-list-item' + (isCurrent ? ' current' : ''),
        style: {
          display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 12px',
          borderBottom: '1px solid var(--border)',
          background: isCurrent ? 'var(--bg-raised, rgba(108,155,255,0.05))' : '',
        },
      });

      // Icon
      row.appendChild(PE.el('span', {
        text: isCurrent ? '\u25C9' : '\u25CB',
        style: { fontSize: '14px', color: isCurrent ? 'var(--accent)' : 'var(--text-muted)' },
      }));

      // Name + meta
      const info = PE.el('div', { style: { flex: '1', minWidth: '0' } });
      info.appendChild(PE.el('div', { text: name, style: { fontWeight: isCurrent ? '600' : '400' } }));

      if (typeof project === 'object') {
        const meta = PE.el('div', { style: { fontSize: '10px', color: 'var(--text-muted)', display: 'flex', gap: '10px' } });
        if (project.created) meta.appendChild(PE.el('span', { text: `Created: ${PE.utils.formatDate(project.created)}` }));
        if (project.modified || project.last_saved) meta.appendChild(PE.el('span', { text: `Modified: ${PE.utils.relativeTime(project.modified || project.last_saved)}` }));
        if (project.flow_count != null) meta.appendChild(PE.el('span', { text: `${project.flow_count} flows` }));
        info.appendChild(meta);
      }

      row.appendChild(info);

      // Actions
      const actions = PE.el('div', { style: { display: 'flex', gap: '4px', flexShrink: '0' } });

      if (!isCurrent) {
        const loadBtn = PE.el('button', { class: 'btn btn-xs btn-primary', text: 'Load' });
        loadBtn.addEventListener('click', () => this._loadProject(name));
        actions.appendChild(loadBtn);
      }

      const deleteBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Delete' });
      deleteBtn.addEventListener('click', () => this._deleteProject(name));
      actions.appendChild(deleteBtn);

      row.appendChild(actions);
      this._els.projectsList.appendChild(row);
    });
  },

  async _saveProject() {
    const name = this._els.nameInput.value.trim();
    if (!name) { PE.toast.warning('Project name is required'); return; }

    try {
      await PE.api.post('/api/projects/save', { name });
      PE.toast.success(`Project "${name}" saved`);
      this.refresh();
    } catch (e) {
      PE.toast.error('Failed to save project: ' + e.message);
    }
  },

  async _loadProject(name) {
    const confirmed = await PE.modal.confirm({
      title: 'Load Project',
      message: `Load project "${name}"? Current unsaved data will be lost.`,
      confirmLabel: 'Load',
    });
    if (!confirmed) return;

    try {
      await PE.api.post('/api/projects/load', { name });
      PE.toast.success(`Project "${name}" loaded`);
      this._currentProject = name;
      this._els.nameInput.value = name;
      this.refresh();
      PE.bus.emit('project:loaded', name);
    } catch (e) {
      PE.toast.error('Failed to load project: ' + e.message);
    }
  },

  async _deleteProject(name) {
    const confirmed = await PE.modal.confirm({
      title: 'Delete Project',
      message: `Permanently delete project "${name}"?`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await PE.api.del(`/api/projects/${encodeURIComponent(name)}`);
      PE.toast.success(`Project "${name}" deleted`);
      if (this._currentProject === name) {
        this._currentProject = null;
      }
      this.refresh();
    } catch (e) {
      PE.toast.error('Failed to delete project: ' + e.message);
    }
  },
};
