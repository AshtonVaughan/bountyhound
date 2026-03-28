/**
 * Settings Panel — Extension toggles, TLS config, live audit config.
 */
PE.panels = PE.panels || {};

PE.panels.settings = {
  _container: null,
  _els: {},

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('settings-panel');

    const scrollWrap = PE.el('div', { style: { overflow: 'auto', height: '100%', padding: '16px' } });

    // ── Extensions Section ────────────────────────────────────────────────
    scrollWrap.appendChild(this._buildSectionHeader('Extensions'));
    this._els.extensionsList = PE.el('div', { class: 'settings-extensions-list' });
    scrollWrap.appendChild(this._els.extensionsList);

    // ── Live Audit Section ────────────────────────────────────────────────
    scrollWrap.appendChild(this._buildSectionHeader('Live Audit'));
    this._els.auditSection = PE.el('div', { class: 'settings-section' });
    scrollWrap.appendChild(this._els.auditSection);

    // ── TLS Configuration Section ─────────────────────────────────────────
    scrollWrap.appendChild(this._buildSectionHeader('TLS Configuration'));
    this._els.tlsSection = PE.el('div', { class: 'settings-section' });
    scrollWrap.appendChild(this._els.tlsSection);

    // ── API Key Section ───────────────────────────────────────────────────
    scrollWrap.appendChild(this._buildSectionHeader('API Key'));
    this._els.apiKeySection = PE.el('div', { class: 'settings-section' });
    scrollWrap.appendChild(this._els.apiKeySection);

    // ── Mobile Proxy Section ──────────────────────────────────────────────
    scrollWrap.appendChild(this._buildSectionHeader('Mobile Proxy'));
    this._els.mobileSection = PE.el('div', { class: 'settings-section' });
    scrollWrap.appendChild(this._els.mobileSection);

    container.appendChild(scrollWrap);

    // ── Events ────────────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'settings') this.refresh();
    });

    this.refresh();
  },

  _buildSectionHeader(title) {
    return PE.el('h3', {
      text: title,
      style: { margin: '18px 0 8px 0', paddingBottom: '4px', borderBottom: '1px solid var(--border)', fontSize: '14px' },
    });
  },

  async refresh() {
    try {
      const [extData, auditData, tlsData, apiData, mobileData] = await Promise.all([
        PE.api.get('/api/extensions').catch(() => ({ extensions: [] })),
        PE.api.get('/api/audit/config').catch(() => ({})),
        PE.api.get('/api/tls/config').catch(() => ({})),
        PE.api.get('/api/settings/apikey').catch(() => ({})),
        PE.api.get('/api/settings/mobile').catch(() => ({})),
      ]);
      this._renderExtensions(extData.extensions || extData || []);
      this._renderAuditConfig(auditData);
      this._renderTLSConfig(tlsData);
      this._renderAPIKey(apiData);
      this._renderMobileConfig(mobileData);
    } catch (e) {
      console.error('[settings] refresh failed:', e);
    }
  },

  // ── Extensions ─────────────────────────────────────────────────────────
  _renderExtensions(extensions) {
    this._els.extensionsList.innerHTML = '';

    if (!extensions.length) {
      this._els.extensionsList.appendChild(PE.el('div', { class: 'empty-state', style: { padding: '16px' } },
        PE.el('div', { class: 'title', text: 'No extensions loaded' })
      ));
      return;
    }

    extensions.forEach((ext) => {
      const row = PE.el('div', {
        class: 'settings-ext-row',
        style: { display: 'flex', alignItems: 'center', padding: '8px 12px', borderBottom: '1px solid var(--border)', gap: '12px' },
      });

      // Toggle switch
      const toggle = PE.el('label', { class: 'toggle-switch' });
      const checkbox = PE.el('input', { type: 'checkbox' });
      checkbox.checked = ext.enabled !== false;
      checkbox.addEventListener('change', () => this._toggleExtension(ext.name || ext.id, checkbox.checked));
      const slider = PE.el('span', { class: 'toggle-slider' });
      toggle.appendChild(checkbox);
      toggle.appendChild(slider);
      row.appendChild(toggle);

      // Info
      const info = PE.el('div', { style: { flex: '1' } });
      info.appendChild(PE.el('div', { text: ext.name || ext.id, style: { fontWeight: '600' } }));
      if (ext.description) {
        info.appendChild(PE.el('div', { text: ext.description, style: { fontSize: '11px', color: 'var(--text-muted)' } }));
      }
      row.appendChild(info);

      // Config button
      if (ext.configurable !== false) {
        const configBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Configure' });
        configBtn.addEventListener('click', () => this._showExtensionConfig(ext));
        row.appendChild(configBtn);
      }

      this._els.extensionsList.appendChild(row);
    });
  },

  async _toggleExtension(name, enabled) {
    try {
      await PE.api.patch(`/api/extensions/${encodeURIComponent(name)}`, { enabled });
      PE.toast.success(`${name} ${enabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle extension: ' + e.message);
    }
  },

  async _showExtensionConfig(ext) {
    let config;
    try {
      config = await PE.api.get(`/api/extensions/${encodeURIComponent(ext.name || ext.id)}/config`);
    } catch (e) {
      PE.toast.error('Failed to load config: ' + e.message);
      return;
    }

    const form = PE.el('div', { style: { display: 'grid', gap: '8px' } });
    const inputs = {};

    for (const [key, value] of Object.entries(config)) {
      form.appendChild(PE.el('label', { text: key, style: { fontWeight: '500', fontSize: '12px' } }));
      if (typeof value === 'boolean') {
        const cb = PE.el('input', { type: 'checkbox' });
        cb.checked = value;
        inputs[key] = cb;
        form.appendChild(cb);
      } else if (typeof value === 'number') {
        const inp = PE.el('input', { type: 'number', class: 'input', value: String(value) });
        inputs[key] = inp;
        form.appendChild(inp);
      } else {
        const inp = PE.el('input', { type: 'text', class: 'input', value: String(value || '') });
        inputs[key] = inp;
        form.appendChild(inp);
      }
    }

    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: 'Save' });
    const cancelBtn = PE.el('button', { class: 'btn', text: 'Cancel' });

    const { close } = PE.modal.show({
      title: `Configure: ${ext.name || ext.id}`,
      body: form,
      footer: [cancelBtn, saveBtn],
      width: '450px',
    });

    cancelBtn.addEventListener('click', () => close());
    saveBtn.addEventListener('click', async () => {
      const newConfig = {};
      for (const [key, el] of Object.entries(inputs)) {
        if (el.type === 'checkbox') newConfig[key] = el.checked;
        else if (el.type === 'number') newConfig[key] = parseFloat(el.value) || 0;
        else newConfig[key] = el.value;
      }
      try {
        await PE.api.put(`/api/extensions/${encodeURIComponent(ext.name || ext.id)}/config`, newConfig);
        close();
        PE.toast.success('Configuration saved');
      } catch (e) {
        PE.toast.error('Failed to save config: ' + e.message);
      }
    });
  },

  // ── Live Audit Config ──────────────────────────────────────────────────
  _renderAuditConfig(config) {
    this._els.auditSection.innerHTML = '';
    const grid = PE.el('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' } });

    // Enabled toggle
    const enabledRow = PE.el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', gridColumn: '1 / -1' } });
    const auditToggle = PE.el('label', { class: 'toggle-switch' });
    const auditCb = PE.el('input', { type: 'checkbox' });
    auditCb.checked = config.enabled !== false;
    auditToggle.appendChild(auditCb);
    auditToggle.appendChild(PE.el('span', { class: 'toggle-slider' }));
    enabledRow.appendChild(auditToggle);
    enabledRow.appendChild(PE.el('span', { text: 'Live audit enabled' }));
    grid.appendChild(enabledRow);

    // Rate limit
    const rateLimitLabel = PE.el('label', { text: 'Rate Limit (req/s)', style: { fontSize: '12px' } });
    const rateLimitInput = PE.el('input', { type: 'number', class: 'input', value: String(config.rate_limit || 10), style: { width: '100px' } });
    grid.appendChild(PE.el('div', {}, rateLimitLabel, rateLimitInput));

    // Check selection
    const checksLabel = PE.el('label', { text: 'Active Checks', style: { fontSize: '12px', display: 'block', marginBottom: '4px' } });
    grid.appendChild(PE.el('div', { style: { gridColumn: '1 / -1' } }, checksLabel));

    const allChecks = config.available_checks || [
      'sqli', 'xss', 'ssti', 'idor', 'cors', 'ssrf', 'lfi', 'rfi',
      'open_redirect', 'crlf', 'xxe', 'jwt', 'auth_bypass', 'info_disclosure',
    ];
    const activeChecks = new Set(config.active_checks || allChecks);
    const checksGrid = PE.el('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: '4px', gridColumn: '1 / -1' } });

    const checkInputs = {};
    allChecks.forEach(check => {
      const label = PE.el('label', { style: { display: 'flex', alignItems: 'center', gap: '4px', fontSize: '12px', cursor: 'pointer' } });
      const cb = PE.el('input', { type: 'checkbox' });
      cb.checked = activeChecks.has(check);
      checkInputs[check] = cb;
      label.appendChild(cb);
      label.appendChild(PE.el('span', { text: check }));
      checksGrid.appendChild(label);
    });
    grid.appendChild(checksGrid);

    // Save button
    const saveBtn = PE.el('button', { class: 'btn btn-primary', text: 'Save Audit Config', style: { marginTop: '8px', gridColumn: '1 / -1' } });
    saveBtn.addEventListener('click', async () => {
      const newChecks = Object.entries(checkInputs).filter(([, cb]) => cb.checked).map(([name]) => name);
      try {
        await PE.api.put('/api/audit/config', {
          enabled: auditCb.checked,
          rate_limit: parseInt(rateLimitInput.value) || 10,
          active_checks: newChecks,
        });
        PE.toast.success('Audit config saved');
      } catch (e) {
        PE.toast.error('Failed to save audit config: ' + e.message);
      }
    });
    grid.appendChild(saveBtn);

    this._els.auditSection.appendChild(grid);
  },

  // ── TLS Configuration ──────────────────────────────────────────────────
  _renderTLSConfig(config) {
    this._els.tlsSection.innerHTML = '';

    // Client certificate
    const certRow = PE.el('div', { style: { marginBottom: '12px' } });
    certRow.appendChild(PE.el('label', { text: 'Client Certificate (PEM)', style: { display: 'block', fontSize: '12px', marginBottom: '4px' } }));
    const certTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '80px', fontFamily: 'monospace', fontSize: '11px', resize: 'vertical' },
      placeholder: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
    });
    certTA.value = config.client_cert || '';
    certRow.appendChild(certTA);

    const keyRow = PE.el('div', { style: { marginBottom: '12px' } });
    keyRow.appendChild(PE.el('label', { text: 'Client Key (PEM)', style: { display: 'block', fontSize: '12px', marginBottom: '4px' } }));
    const keyTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '80px', fontFamily: 'monospace', fontSize: '11px', resize: 'vertical' },
      placeholder: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----',
    });
    keyTA.value = config.client_key || '';
    keyRow.appendChild(keyTA);

    // Passthrough domains
    const passthroughRow = PE.el('div', { style: { marginBottom: '12px' } });
    passthroughRow.appendChild(PE.el('label', { text: 'TLS Passthrough Domains (one per line)', style: { display: 'block', fontSize: '12px', marginBottom: '4px' } }));
    const passthroughTA = PE.el('textarea', {
      class: 'input mono',
      style: { width: '100%', height: '60px', fontFamily: 'monospace', fontSize: '11px', resize: 'vertical' },
      placeholder: 'example.com\n*.google.com',
    });
    passthroughTA.value = (config.passthrough_domains || []).join('\n');
    passthroughRow.appendChild(passthroughTA);

    const saveTlsBtn = PE.el('button', { class: 'btn btn-primary', text: 'Save TLS Config' });
    saveTlsBtn.addEventListener('click', async () => {
      try {
        await PE.api.put('/api/tls/config', {
          client_cert: certTA.value.trim(),
          client_key: keyTA.value.trim(),
          passthrough_domains: passthroughTA.value.split('\n').map(d => d.trim()).filter(Boolean),
        });
        PE.toast.success('TLS config saved');
      } catch (e) {
        PE.toast.error('Failed to save TLS config: ' + e.message);
      }
    });

    this._els.tlsSection.appendChild(certRow);
    this._els.tlsSection.appendChild(keyRow);
    this._els.tlsSection.appendChild(passthroughRow);
    this._els.tlsSection.appendChild(saveTlsBtn);
  },

  // ── API Key ────────────────────────────────────────────────────────────
  _renderAPIKey(data) {
    this._els.apiKeySection.innerHTML = '';

    const keyRow = PE.el('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } });
    const keyDisplay = PE.el('input', {
      type: 'password',
      class: 'input mono',
      value: data.api_key || data.key || '',
      readonly: 'readonly',
      style: { flex: '1', fontFamily: 'monospace', fontSize: '12px' },
    });

    const showBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Show' });
    showBtn.addEventListener('click', () => {
      const isPassword = keyDisplay.type === 'password';
      keyDisplay.type = isPassword ? 'text' : 'password';
      showBtn.textContent = isPassword ? 'Hide' : 'Show';
    });

    const copyBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Copy' });
    copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(keyDisplay.value));

    const regenBtn = PE.el('button', { class: 'btn btn-xs btn-danger', text: 'Regenerate' });
    regenBtn.addEventListener('click', async () => {
      const confirmed = await PE.modal.confirm({
        title: 'Regenerate API Key',
        message: 'This will invalidate the current key. Continue?',
        confirmLabel: 'Regenerate',
        danger: true,
      });
      if (!confirmed) return;
      try {
        const result = await PE.api.post('/api/settings/apikey/regenerate', {});
        keyDisplay.value = result.api_key || result.key || '';
        PE.toast.success('API key regenerated');
      } catch (e) {
        PE.toast.error('Failed to regenerate: ' + e.message);
      }
    });

    keyRow.appendChild(keyDisplay);
    keyRow.appendChild(showBtn);
    keyRow.appendChild(copyBtn);
    keyRow.appendChild(regenBtn);
    this._els.apiKeySection.appendChild(keyRow);
  },

  // ── Mobile Proxy Config ────────────────────────────────────────────────
  _renderMobileConfig(data) {
    this._els.mobileSection.innerHTML = '';

    const info = PE.el('div', { style: { fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' } });
    info.textContent = 'Configure your mobile device to use this proxy. Download the PAC file or scan the QR code.';
    this._els.mobileSection.appendChild(info);

    const linksRow = PE.el('div', { style: { display: 'flex', gap: '12px', flexWrap: 'wrap' } });

    // PAC file link
    if (data.pac_url) {
      const pacLink = PE.el('a', {
        href: data.pac_url,
        text: 'Download PAC File',
        class: 'btn btn-sm btn-primary',
        style: { textDecoration: 'none' },
      });
      pacLink.setAttribute('download', 'proxy.pac');
      linksRow.appendChild(pacLink);
    }

    // CA cert link
    if (data.ca_url) {
      const caLink = PE.el('a', {
        href: data.ca_url,
        text: 'Download CA Certificate',
        class: 'btn btn-sm',
        style: { textDecoration: 'none' },
      });
      caLink.setAttribute('download', 'ca-cert.pem');
      linksRow.appendChild(caLink);
    }

    this._els.mobileSection.appendChild(linksRow);

    // QR Code
    if (data.qr_pac_url || data.qr_ca_url) {
      const qrRow = PE.el('div', { style: { display: 'flex', gap: '24px', marginTop: '16px' } });

      if (data.qr_pac_url) {
        const pacQr = PE.el('div', { style: { textAlign: 'center' } });
        pacQr.appendChild(PE.el('img', { src: data.qr_pac_url, style: { width: '140px', height: '140px', borderRadius: '4px' }, alt: 'PAC QR' }));
        pacQr.appendChild(PE.el('div', { text: 'PAC File', style: { fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' } }));
        qrRow.appendChild(pacQr);
      }

      if (data.qr_ca_url) {
        const caQr = PE.el('div', { style: { textAlign: 'center' } });
        caQr.appendChild(PE.el('img', { src: data.qr_ca_url, style: { width: '140px', height: '140px', borderRadius: '4px' }, alt: 'CA QR' }));
        caQr.appendChild(PE.el('div', { text: 'CA Certificate', style: { fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' } }));
        qrRow.appendChild(caQr);
      }

      this._els.mobileSection.appendChild(qrRow);
    }

    // Proxy address display
    const addrRow = PE.el('div', { style: { marginTop: '12px', fontSize: '12px' } });
    const proxyHost = data.proxy_host || location.hostname || '127.0.0.1';
    const proxyPort = data.proxy_port || '8080';
    addrRow.appendChild(PE.el('span', { text: 'Proxy Address: ', style: { color: 'var(--text-muted)' } }));
    addrRow.appendChild(PE.el('code', { text: `${proxyHost}:${proxyPort}`, style: { fontFamily: 'monospace', fontWeight: '600' } }));
    const copyAddrBtn = PE.el('button', { class: 'btn btn-xs btn-ghost', text: 'Copy', style: { marginLeft: '8px' } });
    copyAddrBtn.addEventListener('click', () => PE.utils.copyToClipboard(`${proxyHost}:${proxyPort}`));
    addrRow.appendChild(copyAddrBtn);
    this._els.mobileSection.appendChild(addrRow);
  },
};
