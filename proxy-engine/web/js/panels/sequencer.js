/**
 * Sequencer Panel — Token analysis with entropy visualization and character frequency charts.
 */
PE.panels = PE.panels || {};

PE.panels.sequencer = {
  _container: null,
  _running: false,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('sequencer-panel');

    // ── Config Form ────────────────────────────────────────────────────────
    const configCard = PE.el('div', { class: 'panel-card' });
    configCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Token Analysis Configuration' }));

    const form = PE.el('div', { class: 'form-grid' });

    // URL
    form.appendChild(PE.el('label', { class: 'form-label', text: 'URL' }));
    this._urlInput = PE.el('input', { class: 'input', type: 'text', placeholder: 'https://example.com/api/token' });
    form.appendChild(this._urlInput);

    // Method
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Method' }));
    this._methodSelect = PE.el('select', { class: 'input' });
    for (const m of ['GET', 'POST', 'PUT', 'PATCH']) {
      this._methodSelect.appendChild(PE.el('option', { value: m, text: m }));
    }
    form.appendChild(this._methodSelect);

    // Headers
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Headers (JSON)' }));
    this._headersInput = PE.el('textarea', { class: 'input', rows: '3', placeholder: '{"Authorization": "Bearer ..."}' });
    form.appendChild(this._headersInput);

    // Token location
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Token Location' }));
    this._locationSelect = PE.el('select', { class: 'input' });
    for (const loc of ['response_body', 'response_header', 'cookie', 'json_path']) {
      this._locationSelect.appendChild(PE.el('option', { value: loc, text: loc.replace(/_/g, ' ') }));
    }
    form.appendChild(this._locationSelect);

    // Token name / path
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Token Name / Path' }));
    this._tokenNameInput = PE.el('input', { class: 'input', type: 'text', placeholder: 'e.g. session_id, $.data.token, Set-Cookie' });
    form.appendChild(this._tokenNameInput);

    // Sample count
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Sample Count' }));
    this._sampleInput = PE.el('input', { class: 'input', type: 'number', value: '100', min: '10', max: '10000' });
    form.appendChild(this._sampleInput);

    // Request body (for POST)
    form.appendChild(PE.el('label', { class: 'form-label', text: 'Request Body' }));
    this._bodyInput = PE.el('textarea', { class: 'input', rows: '3', placeholder: 'Optional request body for POST requests' });
    form.appendChild(this._bodyInput);

    configCard.appendChild(form);

    // Start / Stop buttons
    const btnRow = PE.el('div', { class: 'form-actions' });
    this._startBtn = PE.el('button', { class: 'btn btn-primary', text: 'Start Analysis' });
    this._startBtn.addEventListener('click', () => this._startAnalysis());
    btnRow.appendChild(this._startBtn);

    this._stopBtn = PE.el('button', { class: 'btn btn-danger', text: 'Stop', style: { display: 'none' } });
    this._stopBtn.addEventListener('click', () => this._stopAnalysis());
    btnRow.appendChild(this._stopBtn);

    this._progressLabel = PE.el('span', { class: 'toolbar-count', text: '' });
    btnRow.appendChild(this._progressLabel);

    configCard.appendChild(btnRow);
    container.appendChild(configCard);

    // ── Results Area ───────────────────────────────────────────────────────
    this._resultsCard = PE.el('div', { class: 'panel-card', style: { display: 'none' } });
    this._resultsCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Analysis Results' }));

    // Summary stats row
    this._summaryRow = PE.el('div', { class: 'dash-stats-row' });
    this._resultsCard.appendChild(this._summaryRow);

    // Entropy rating
    this._ratingEl = PE.el('div', { class: 'sequencer-rating' });
    this._resultsCard.appendChild(this._ratingEl);

    // Character frequency chart
    this._charFreqTitle = PE.el('div', { class: 'panel-card-title', text: 'Character Frequency Distribution', style: { marginTop: '16px' } });
    this._resultsCard.appendChild(this._charFreqTitle);
    this._charFreqChart = PE.el('div', { class: 'sequencer-chart' });
    this._resultsCard.appendChild(this._charFreqChart);

    // Length statistics
    this._lengthTitle = PE.el('div', { class: 'panel-card-title', text: 'Token Length Statistics', style: { marginTop: '16px' } });
    this._resultsCard.appendChild(this._lengthTitle);
    this._lengthStats = PE.el('div', { class: 'sequencer-length-stats' });
    this._resultsCard.appendChild(this._lengthStats);

    // Sample tokens
    this._samplesTitle = PE.el('div', { class: 'panel-card-title', text: 'Sample Tokens', style: { marginTop: '16px' } });
    this._resultsCard.appendChild(this._samplesTitle);
    this._samplesList = PE.el('div', { class: 'sequencer-samples' });
    this._resultsCard.appendChild(this._samplesList);

    container.appendChild(this._resultsCard);

    // ── Listen for load-from-flow events ───────────────────────────────────
    PE.bus.on('sequencer:loadFlow', (flow) => {
      if (flow && flow.request) {
        this._urlInput.value = flow.request.url || flow.url || '';
        this._methodSelect.value = (flow.request.method || 'GET').toUpperCase();
        if (flow.request.headers) {
          this._headersInput.value = JSON.stringify(flow.request.headers, null, 2);
        }
        if (flow.request.body) {
          this._bodyInput.value = flow.request.body;
        }
      }
    });
  },

  async _startAnalysis() {
    const url = this._urlInput.value.trim();
    if (!url) {
      PE.toast.warning('Enter a URL to analyze');
      return;
    }

    let headers = {};
    const headersRaw = this._headersInput.value.trim();
    if (headersRaw) {
      try {
        headers = JSON.parse(headersRaw);
      } catch (e) {
        PE.toast.error('Invalid headers JSON: ' + e.message);
        return;
      }
    }

    const config = {
      url,
      method: this._methodSelect.value,
      headers,
      token_location: this._locationSelect.value,
      token_name: this._tokenNameInput.value.trim(),
      sample_count: parseInt(this._sampleInput.value) || 100,
      body: this._bodyInput.value.trim() || undefined,
    };

    this._running = true;
    this._startBtn.style.display = 'none';
    this._stopBtn.style.display = '';
    this._progressLabel.textContent = 'Collecting tokens...';

    try {
      const result = await PE.api.post('/api/sequencer/start', config);
      this._renderResults(result);
      PE.toast.success('Analysis complete');
    } catch (e) {
      PE.toast.error('Analysis failed: ' + e.message);
    } finally {
      this._running = false;
      this._startBtn.style.display = '';
      this._stopBtn.style.display = 'none';
      this._progressLabel.textContent = '';
    }
  },

  async _stopAnalysis() {
    try {
      await PE.api.post('/api/sequencer/stop');
      PE.toast.info('Analysis stopped');
    } catch (e) {
      PE.toast.error('Failed to stop: ' + e.message);
    }
    this._running = false;
    this._startBtn.style.display = '';
    this._stopBtn.style.display = 'none';
    this._progressLabel.textContent = '';
  },

  _renderResults(result) {
    this._resultsCard.style.display = '';

    // Summary stats
    this._summaryRow.innerHTML = '';
    const stats = [
      { label: 'Entropy (bits)', value: (result.entropy_bits ?? 0).toFixed(2) },
      { label: 'Samples Collected', value: String(result.sample_count || 0) },
      { label: 'Unique Tokens', value: String(result.unique_count || 0) },
      { label: 'Charset Size', value: String(result.charset_size || 0) },
    ];
    for (const s of stats) {
      const card = PE.el('div', { class: 'dash-stat-card' });
      card.appendChild(PE.el('div', { class: 'dash-stat-value', text: s.value }));
      card.appendChild(PE.el('div', { class: 'dash-stat-label', text: s.label }));
      this._summaryRow.appendChild(card);
    }

    // Entropy rating
    const entropy = result.entropy_bits || 0;
    const rating = this._getEntropyRating(entropy);
    this._ratingEl.innerHTML = `
      <div class="sequencer-rating-bar">
        <div class="sequencer-rating-fill ${rating.cls}" style="width: ${Math.min(100, (entropy / 128) * 100).toFixed(1)}%"></div>
      </div>
      <div class="sequencer-rating-text">
        <strong>${rating.label}</strong> &mdash; ${rating.description}
      </div>
    `;

    // Character frequency chart
    const charFreq = result.char_frequency || {};
    const sortedChars = Object.entries(charFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 40);

    if (sortedChars.length > 0) {
      const barData = sortedChars.map(([ch, count]) => ({
        label: ch === ' ' ? 'SP' : ch,
        value: count,
        color: this._charColor(ch),
      }));
      const chartWidth = Math.max(400, barData.length * 16);
      PE.chart.bar(this._charFreqChart, barData, { width: chartWidth, height: 160, barWidth: 10 });
    } else {
      this._charFreqChart.innerHTML = '<div class="empty-state"><div class="title">No character data</div></div>';
    }

    // Length stats
    const lengths = result.length_stats || {};
    this._lengthStats.innerHTML = `
      <div class="stats-grid">
        <div class="stat-item"><span class="stat-label">Min Length</span><span class="stat-value">${lengths.min ?? '-'}</span></div>
        <div class="stat-item"><span class="stat-label">Max Length</span><span class="stat-value">${lengths.max ?? '-'}</span></div>
        <div class="stat-item"><span class="stat-label">Mean Length</span><span class="stat-value">${(lengths.mean ?? 0).toFixed(1)}</span></div>
        <div class="stat-item"><span class="stat-label">Std Dev</span><span class="stat-value">${(lengths.std_dev ?? 0).toFixed(2)}</span></div>
        <div class="stat-item"><span class="stat-label">Mode</span><span class="stat-value">${lengths.mode ?? '-'}</span></div>
        <div class="stat-item"><span class="stat-label">All Same Length</span><span class="stat-value">${lengths.min === lengths.max ? 'Yes' : 'No'}</span></div>
      </div>
    `;

    // Sample tokens
    const samples = result.samples || [];
    if (samples.length > 0) {
      this._samplesList.innerHTML = '';
      const list = PE.el('div', { class: 'samples-list' });
      for (const token of samples.slice(0, 20)) {
        const row = PE.el('div', { class: 'sample-row' });
        row.appendChild(PE.el('code', { class: 'sample-token', text: token }));
        const copyBtn = PE.el('button', { class: 'btn btn-xs', text: 'Copy' });
        copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(token));
        row.appendChild(copyBtn);
        list.appendChild(row);
      }
      this._samplesList.appendChild(list);
    } else {
      this._samplesList.innerHTML = '<div class="empty-state"><div class="title">No sample tokens</div></div>';
    }
  },

  _getEntropyRating(bits) {
    if (bits >= 128) return { label: 'Excellent', cls: 'rating-excellent', description: 'Token randomness is very strong. Prediction is infeasible.' };
    if (bits >= 64) return { label: 'Good', cls: 'rating-good', description: 'Token randomness is adequate for most purposes.' };
    if (bits >= 32) return { label: 'Fair', cls: 'rating-fair', description: 'Token randomness may be insufficient. Consider strengthening.' };
    if (bits >= 16) return { label: 'Poor', cls: 'rating-poor', description: 'Token randomness is weak. Prediction may be feasible.' };
    return { label: 'Critical', cls: 'rating-critical', description: 'Token randomness is extremely weak. Tokens are predictable.' };
  },

  _charColor(ch) {
    if (/[0-9]/.test(ch)) return 'var(--accent, #6c9bff)';
    if (/[a-f]/i.test(ch)) return 'var(--sev-medium, #fcbf49)';
    if (/[g-z]/i.test(ch)) return 'var(--sev-low, #2a9d8f)';
    if (ch === '=' || ch === '+' || ch === '/') return 'var(--sev-high, #f77f00)';
    return 'var(--text-dim)';
  },
};
