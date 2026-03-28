/**
 * Browser Scan Panel — URL + check selection -> POST /api/scanner/browser-scan
 * Results table display with polling for status updates.
 */
PE.panels = PE.panels || {};

PE.panels['browser-scan'] = {
    _container: null,
    _results: [],
    _scanning: false,

    init(container) {
        this._container = container;
        this._render();
    },

    refresh() {
        this._render();
    },

    async startScan() {
        const url = document.getElementById('bs-url')?.value;
        if (!url) { PE.toast.error('Enter a URL'); return; }

        const checkboxes = document.querySelectorAll('.bs-check:checked');
        const checks = Array.from(checkboxes).map(cb => cb.value);
        if (!checks.length) { PE.toast.error('Select at least one check'); return; }

        this._scanning = true;
        this._render();

        try {
            const resp = await PE.api.post('/api/scanner/browser-scan', { url, checks });
            if (resp && resp.job_id) {
                PE.toast.info('Browser scan started: ' + resp.job_id);
                this._pollResults(resp.job_id);
            }
        } catch(e) {
            PE.toast.error('Scan failed: ' + e.message);
            this._scanning = false;
            this._render();
        }
    },

    _pollResults(jobId) {
        const poll = async () => {
            try {
                const resp = await PE.api.get(`/api/scanner/${jobId}`);
                if (resp) {
                    this._results = resp.findings || [];
                    this._renderResults();
                    if (resp.status === 'running') {
                        setTimeout(poll, 2000);
                    } else {
                        this._scanning = false;
                        this._render();
                        PE.tabManager.incrementBadge('browser-scan');
                    }
                }
            } catch(e) {
                this._scanning = false;
                this._render();
            }
        };
        poll();
    },

    _renderResults() {
        const container = document.getElementById('bs-results');
        if (!container) return;
        if (!this._results.length) {
            container.innerHTML = '<div class="empty-state"><div class="title">No findings yet</div></div>';
            return;
        }
        container.innerHTML = `
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Name</th>
                        <th>URL</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    ${this._results.map(f => `
                        <tr class="sev-row-${f.severity || 'info'}">
                            <td><span class="sev-${f.severity || 'info'} badge">${PE.utils.escapeHtml((f.severity || 'info').toUpperCase())}</span></td>
                            <td>${PE.utils.escapeHtml(f.name || f.template_id || '')}</td>
                            <td class="url-cell" title="${PE.utils.escapeHtml(f.url || '')}">${PE.utils.escapeHtml((f.url || '').substring(0, 50))}</td>
                            <td>${PE.utils.escapeHtml((f.description || '').substring(0, 100))}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    _render() {
        const el = this._container;
        if (!el) return;

        const domChecks = [
            'dom_xss', 'dom_clobbering', 'postmessage_xss',
            'prototype_pollution_client', 'sourcemap_disclosure'
        ];

        // Preserve URL input value across re-renders
        const currentUrl = document.getElementById('bs-url')?.value || '';

        el.innerHTML = `
            <div class="panel-toolbar">
                <input type="text" id="bs-url" placeholder="https://target.com" class="input-wide"
                    value="${PE.utils.escapeHtml(currentUrl)}">
                <button class="btn btn-primary"
                    onclick="PE.panels['browser-scan'].startScan()"
                    ${this._scanning ? 'disabled' : ''}>
                    ${this._scanning ? 'Scanning...' : 'Start Scan'}
                </button>
            </div>
            <div class="panel-config">
                <label>Checks:</label>
                <div class="check-grid">
                    ${domChecks.map(c => `
                        <label class="check-label">
                            <input type="checkbox" class="bs-check" value="${c}" checked>
                            ${c.replace(/_/g, ' ')}
                        </label>
                    `).join('')}
                </div>
            </div>
            <div id="bs-results" class="results-container">
                <div class="empty-state"><div class="title">Configure and start a browser-based scan</div></div>
            </div>
        `;
    }
};
