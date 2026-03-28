/**
 * Collaborator Panel — OOB payload generator with interaction feed and auto-refresh.
 */
PE.panels = PE.panels || {};

PE.panels.collaborator = {
  _container: null,
  _payloads: [],
  _interactions: [],
  _refreshTimer: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('collaborator-panel');

    // ── Server Config ──────────────────────────────────────────────────────
    const configCard = PE.el('div', { class: 'panel-card' });
    configCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Collaborator Server' }));

    const configForm = PE.el('div', { class: 'form-grid' });

    configForm.appendChild(PE.el('label', { class: 'form-label', text: 'Domain' }));
    this._domainInput = PE.el('input', { class: 'input', type: 'text', placeholder: 'collab.example.com' });
    configForm.appendChild(this._domainInput);

    configForm.appendChild(PE.el('label', { class: 'form-label', text: 'DNS Port' }));
    this._dnsPortInput = PE.el('input', { class: 'input', type: 'number', value: '53', min: '1', max: '65535' });
    configForm.appendChild(this._dnsPortInput);

    configForm.appendChild(PE.el('label', { class: 'form-label', text: 'HTTP Port' }));
    this._httpPortInput = PE.el('input', { class: 'input', type: 'number', value: '8880', min: '1', max: '65535' });
    configForm.appendChild(this._httpPortInput);

    configForm.appendChild(PE.el('label', { class: 'form-label', text: 'SMTP Port' }));
    this._smtpPortInput = PE.el('input', { class: 'input', type: 'number', value: '25', min: '1', max: '65535' });
    configForm.appendChild(this._smtpPortInput);

    configCard.appendChild(configForm);

    // Server control buttons
    const serverBtns = PE.el('div', { class: 'form-actions' });

    this._startBtn = PE.el('button', { class: 'btn btn-primary', text: 'Start Server' });
    this._startBtn.addEventListener('click', () => this._startServer());
    serverBtns.appendChild(this._startBtn);

    this._stopBtn = PE.el('button', { class: 'btn btn-danger', text: 'Stop Server', style: { display: 'none' } });
    this._stopBtn.addEventListener('click', () => this._stopServer());
    serverBtns.appendChild(this._stopBtn);

    this._statusLabel = PE.el('span', { class: 'toolbar-count', text: 'Stopped' });
    serverBtns.appendChild(this._statusLabel);

    configCard.appendChild(serverBtns);
    container.appendChild(configCard);

    // ── Payload Generator ──────────────────────────────────────────────────
    const genCard = PE.el('div', { class: 'panel-card' });
    const genHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    genHeader.appendChild(PE.el('span', { text: 'Generate Payloads' }));

    const clearPayloadsBtn = PE.el('button', { class: 'btn btn-xs', text: 'Clear All' });
    clearPayloadsBtn.addEventListener('click', () => {
      this._payloads = [];
      this._renderPayloads();
    });
    genHeader.appendChild(clearPayloadsBtn);

    genCard.appendChild(genHeader);

    const genForm = PE.el('div', { class: 'form-row' });

    this._contextInput = PE.el('input', { class: 'input', type: 'text', placeholder: 'Context label (e.g. param-name, header-x)', style: { flex: '1' } });
    genForm.appendChild(this._contextInput);

    const genBtn = PE.el('button', { class: 'btn btn-primary', text: 'Generate Payload' });
    genBtn.addEventListener('click', () => this._generatePayload());
    genForm.appendChild(genBtn);

    genCard.appendChild(genForm);

    // Payload list
    this._payloadList = PE.el('div', { class: 'collaborator-payload-list' });
    genCard.appendChild(this._payloadList);

    container.appendChild(genCard);

    // ── Interaction Feed ───────────────────────────────────────────────────
    const feedCard = PE.el('div', { class: 'panel-card', style: { flex: '1' } });
    const feedHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    feedHeader.appendChild(PE.el('span', { text: 'Interaction Feed' }));

    const feedActions = PE.el('div', {});
    this._autoRefreshBtn = PE.el('button', { class: 'btn btn-xs active', text: 'Auto-Refresh: ON' });
    this._autoRefresh = true;
    this._autoRefreshBtn.addEventListener('click', () => this._toggleAutoRefresh());
    feedActions.appendChild(this._autoRefreshBtn);

    const refreshBtn = PE.el('button', { class: 'btn btn-xs', text: 'Refresh Now', style: { marginLeft: '4px' } });
    refreshBtn.addEventListener('click', () => this._fetchInteractions());
    feedActions.appendChild(refreshBtn);

    const clearFeedBtn = PE.el('button', { class: 'btn btn-xs', text: 'Clear', style: { marginLeft: '4px' } });
    clearFeedBtn.addEventListener('click', async () => {
      try {
        await PE.api.del('/api/collaborator/interactions');
        this._interactions = [];
        this._renderInteractions();
      } catch (e) {
        PE.toast.error('Failed to clear interactions: ' + e.message);
      }
    });
    feedActions.appendChild(clearFeedBtn);

    feedHeader.appendChild(feedActions);
    feedCard.appendChild(feedHeader);

    this._interactionCount = PE.el('div', { class: 'toolbar-count', text: '0 interactions' });
    feedCard.appendChild(this._interactionCount);

    this._feedList = PE.el('div', { class: 'collaborator-feed' });
    feedCard.appendChild(this._feedList);

    container.appendChild(feedCard);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('collab:interaction', (interaction) => {
      this._interactions.unshift(interaction);
      this._renderInteractions();
    });

    PE.bus.on('panel:activated', (id) => {
      if (id === 'collaborator') {
        this._fetchInteractions();
        this._fetchServerStatus();
      }
    });

    // Start auto-refresh
    this._startAutoRefresh();
    this._fetchServerStatus();
  },

  async _startServer() {
    const config = {
      domain: this._domainInput.value.trim(),
      dns_port: parseInt(this._dnsPortInput.value) || 53,
      http_port: parseInt(this._httpPortInput.value) || 8880,
      smtp_port: parseInt(this._smtpPortInput.value) || 25,
    };

    if (!config.domain) {
      PE.toast.warning('Enter a domain for the collaborator server');
      return;
    }

    try {
      await PE.api.post('/api/collaborator/start', config);
      this._startBtn.style.display = 'none';
      this._stopBtn.style.display = '';
      this._statusLabel.textContent = 'Running';
      this._statusLabel.classList.add('status-active');
      PE.toast.success('Collaborator server started');
    } catch (e) {
      PE.toast.error('Failed to start server: ' + e.message);
    }
  },

  async _stopServer() {
    try {
      await PE.api.post('/api/collaborator/stop');
      this._startBtn.style.display = '';
      this._stopBtn.style.display = 'none';
      this._statusLabel.textContent = 'Stopped';
      this._statusLabel.classList.remove('status-active');
      PE.toast.info('Collaborator server stopped');
    } catch (e) {
      PE.toast.error('Failed to stop server: ' + e.message);
    }
  },

  async _fetchServerStatus() {
    try {
      const status = await PE.api.get('/api/collaborator/status');
      if (status.running) {
        this._startBtn.style.display = 'none';
        this._stopBtn.style.display = '';
        this._statusLabel.textContent = 'Running';
        this._statusLabel.classList.add('status-active');
        if (status.domain) this._domainInput.value = status.domain;
        if (status.dns_port) this._dnsPortInput.value = String(status.dns_port);
        if (status.http_port) this._httpPortInput.value = String(status.http_port);
        if (status.smtp_port) this._smtpPortInput.value = String(status.smtp_port);
      } else {
        this._startBtn.style.display = '';
        this._stopBtn.style.display = 'none';
        this._statusLabel.textContent = 'Stopped';
        this._statusLabel.classList.remove('status-active');
      }
    } catch (_) {}
  },

  async _generatePayload() {
    const context = this._contextInput.value.trim() || 'default';
    try {
      const result = await PE.api.post('/api/collaborator/generate', { context });
      const payload = {
        id: result.correlation_id || PE.utils.genId(),
        context,
        dns_url: result.dns_url || '',
        http_url: result.http_url || '',
        smtp_url: result.smtp_url || '',
        created: Date.now() / 1000,
      };
      this._payloads.unshift(payload);
      this._renderPayloads();
      PE.toast.success('Payload generated');
      this._contextInput.value = '';
    } catch (e) {
      PE.toast.error('Failed to generate payload: ' + e.message);
    }
  },

  _renderPayloads() {
    this._payloadList.innerHTML = '';

    if (this._payloads.length === 0) {
      this._payloadList.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: 'No payloads generated yet' })
      ));
      return;
    }

    for (const payload of this._payloads) {
      const item = PE.el('div', { class: 'collaborator-payload-item' });

      const header = PE.el('div', { class: 'payload-header' });
      header.appendChild(PE.el('span', { class: 'payload-context', text: payload.context }));
      header.appendChild(PE.el('span', { class: 'payload-id', text: payload.id }));
      item.appendChild(header);

      const urls = [
        { label: 'DNS', value: payload.dns_url },
        { label: 'HTTP', value: payload.http_url },
        { label: 'SMTP', value: payload.smtp_url },
      ];

      for (const url of urls) {
        if (!url.value) continue;
        const row = PE.el('div', { class: 'payload-url-row' });
        row.appendChild(PE.el('span', { class: 'payload-protocol badge', text: url.label }));
        row.appendChild(PE.el('code', { class: 'payload-url', text: url.value }));

        const copyBtn = PE.el('button', { class: 'btn btn-xs', text: 'Copy' });
        copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(url.value));
        row.appendChild(copyBtn);

        item.appendChild(row);
      }

      this._payloadList.appendChild(item);
    }
  },

  async _fetchInteractions() {
    try {
      const data = await PE.api.get('/api/collaborator/interactions');
      this._interactions = Array.isArray(data) ? data : (data.interactions || []);
      this._interactions.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      this._renderInteractions();
    } catch (_) {}
  },

  _renderInteractions() {
    this._feedList.innerHTML = '';
    this._interactionCount.textContent = `${this._interactions.length} interactions`;

    if (this._interactions.length === 0) {
      this._feedList.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: 'No interactions received yet' }),
        PE.el('div', { text: 'Deploy payloads and wait for callbacks' })
      ));
      return;
    }

    for (const interaction of this._interactions) {
      const item = PE.el('div', { class: 'collaborator-interaction' });

      const protocolClass = (interaction.protocol || 'unknown').toLowerCase();

      item.innerHTML = `
        <div class="interaction-header">
          <span class="interaction-time">${PE.utils.escapeHtml(PE.utils.formatDate(interaction.timestamp))}</span>
          <span class="badge interaction-protocol protocol-${PE.utils.escapeHtml(protocolClass)}">${PE.utils.escapeHtml((interaction.protocol || 'UNKNOWN').toUpperCase())}</span>
          <span class="interaction-correlation">${PE.utils.escapeHtml(interaction.correlation_id || '')}</span>
        </div>
        <div class="interaction-details">
          <span class="interaction-label">From:</span>
          <span class="interaction-value">${PE.utils.escapeHtml(interaction.remote_address || interaction.remote_ip || 'unknown')}</span>
        </div>
        ${interaction.raw_data ? `<div class="interaction-raw"><pre>${PE.utils.escapeHtml(PE.utils.truncate(interaction.raw_data, 200))}</pre></div>` : ''}
      `;

      // Match to context
      const matchedPayload = this._payloads.find(p => p.id === interaction.correlation_id);
      if (matchedPayload) {
        const contextEl = PE.el('div', { class: 'interaction-context' });
        contextEl.textContent = `Context: ${matchedPayload.context}`;
        item.appendChild(contextEl);
      }

      this._feedList.appendChild(item);
    }
  },

  _toggleAutoRefresh() {
    this._autoRefresh = !this._autoRefresh;
    this._autoRefreshBtn.textContent = `Auto-Refresh: ${this._autoRefresh ? 'ON' : 'OFF'}`;
    this._autoRefreshBtn.classList.toggle('active', this._autoRefresh);

    if (this._autoRefresh) {
      this._startAutoRefresh();
    } else {
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }
  },

  _startAutoRefresh() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    this._refreshTimer = setInterval(() => {
      if (this._autoRefresh && PE.state.activePanel === 'collaborator') {
        this._fetchInteractions();
      }
    }, 5000);
  },
};
