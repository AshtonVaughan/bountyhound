/**
 * Live Audit Panel — toggle on/off, configure checks, severity threshold, rate limit.
 * Real-time findings feed via SSE.
 */
PE.panels = PE.panels || {};

PE.panels['live-audit'] = {
    _container: null,
    _findings: [],
    _sseSource: null,
    _config: {
        enabled: false,
        checks: ['sqli', 'xss', 'ssti', 'cors', 'open_redirect'],
        severity_threshold: 'medium',
        rate_limit_per_host: 2.0
    },

    init(container) {
        this._container = container;
        this._render();
        this._loadConfig();
    },

    refresh() {
        this._render();
    },

    async _loadConfig() {
        try {
            const resp = await PE.api.get('/api/live-audit/config');
            if (resp) Object.assign(this._config, resp);
            this._render();
        } catch(e) {
            // Config endpoint may not exist yet; use defaults
        }
    },

    async toggleEnabled() {
        this._config.enabled = !this._config.enabled;
        try {
            await PE.api.post('/api/live-audit/config', this._config);
        } catch(e) {
            PE.toast.error('Failed to update live audit config');
        }
        if (this._config.enabled) this._startSSE();
        else this._stopSSE();
        this._render();
    },

    _startSSE() {
        if (this._sseSource) this._sseSource.close();
        this._sseSource = new EventSource('/api/live-audit/stream');
        this._sseSource.onmessage = (e) => {
            try {
                const finding = JSON.parse(e.data);
                this._findings.unshift(finding);
                if (this._findings.length > 500) this._findings.length = 500;
                this._renderFindings();
                PE.tabManager.incrementBadge('live-audit');
            } catch(err) {}
        };
        this._sseSource.onerror = () => {
            // SSE disconnected; will auto-reconnect
        };
    },

    _stopSSE() {
        if (this._sseSource) {
            this._sseSource.close();
            this._sseSource = null;
        }
    },

    async updateConfig() {
        const threshold = document.getElementById('la-severity')?.value || 'medium';
        const rateLimit = parseFloat(document.getElementById('la-rate')?.value || '2.0');
        const checkboxes = document.querySelectorAll('.la-check:checked');
        const checks = Array.from(checkboxes).map(cb => cb.value);
        this._config.severity_threshold = threshold;
        this._config.rate_limit_per_host = rateLimit;
        this._config.checks = checks;
        try {
            await PE.api.post('/api/live-audit/config', this._config);
            PE.toast.success('Live audit config updated');
        } catch(e) {
            PE.toast.error('Failed to update config');
        }
    },

    async clearFindings() {
        this._findings = [];
        try {
            await PE.api.del('/api/live-audit/findings');
        } catch(e) {}
        this._render();
    },

    _renderFindings() {
        const container = document.getElementById('la-findings');
        if (!container) return;
        if (!this._findings.length) {
            container.innerHTML = '<div class="empty-state"><div class="title">No findings yet</div></div>';
            return;
        }
        container.innerHTML = this._findings.slice(0, 100).map(f => `
            <div class="finding-row sev-${f.severity || 'info'}">
                <span class="finding-severity">${PE.utils.escapeHtml((f.severity || 'info').toUpperCase())}</span>
                <span class="finding-name">${PE.utils.escapeHtml(f.name || f.template_id || 'Unknown')}</span>
                <span class="finding-url" title="${PE.utils.escapeHtml(f.url || '')}">${PE.utils.escapeHtml((f.url || '').substring(0, 60))}</span>
            </div>
        `).join('');
    },

    _render() {
        const el = this._container;
        if (!el) return;

        const allChecks = [
            'sqli', 'xss', 'ssti', 'cors', 'open_redirect',
            'ssrf', 'crlf', 'path_traversal', 'command_injection', 'timing_sqli'
        ];

        el.innerHTML = `
            <div class="panel-toolbar">
                <button class="btn ${this._config.enabled ? 'btn-danger' : 'btn-primary'}"
                    onclick="PE.panels['live-audit'].toggleEnabled()">
                    ${this._config.enabled ? 'Stop Audit' : 'Start Audit'}
                </button>
                <button class="btn btn-secondary" onclick="PE.panels['live-audit'].clearFindings()">Clear</button>
                <span class="toolbar-info">${this._findings.length} findings</span>
            </div>
            <div class="panel-config">
                <div class="config-row">
                    <label>Severity Threshold:</label>
                    <select id="la-severity" onchange="PE.panels['live-audit'].updateConfig()">
                        ${['info', 'low', 'medium', 'high', 'critical'].map(s =>
                            `<option value="${s}" ${s === this._config.severity_threshold ? 'selected' : ''}>${s}</option>`
                        ).join('')}
                    </select>
                </div>
                <div class="config-row">
                    <label>Rate Limit (req/s/host):</label>
                    <input type="number" id="la-rate" value="${this._config.rate_limit_per_host}"
                        step="0.5" min="0.1" max="50"
                        onchange="PE.panels['live-audit'].updateConfig()">
                </div>
                <div class="config-row">
                    <label>Checks:</label>
                    <div class="check-grid">
                        ${allChecks.map(c => `
                            <label class="check-label">
                                <input type="checkbox" class="la-check" value="${c}"
                                    ${this._config.checks.includes(c) ? 'checked' : ''}
                                    onchange="PE.panels['live-audit'].updateConfig()">
                                ${c}
                            </label>
                        `).join('')}
                    </div>
                </div>
            </div>
            <div id="la-findings" class="findings-list"></div>
        `;
        this._renderFindings();
    }
};
