/**
 * Decoder Panel — Encode/decode chain builder with history tracking.
 */
PE.panels = PE.panels || {};

PE.panels.decoder = {
  _container: null,
  _history: [],

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('decoder-panel');

    // ── Input Area ─────────────────────────────────────────────────────────
    const inputCard = PE.el('div', { class: 'panel-card' });
    inputCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Input' }));

    this._inputArea = PE.el('textarea', {
      class: 'input decoder-textarea',
      rows: '6',
      placeholder: 'Enter text to encode/decode...',
    });
    inputCard.appendChild(this._inputArea);
    container.appendChild(inputCard);

    // ── Mode Toggle ────────────────────────────────────────────────────────
    const modeRow = PE.el('div', { class: 'decoder-mode-row' });

    this._encodeBtn = PE.el('button', { class: 'btn btn-sm active', text: 'Encode' });
    this._decodeBtn = PE.el('button', { class: 'btn btn-sm', text: 'Decode' });
    this._mode = 'encode';

    this._encodeBtn.addEventListener('click', () => {
      this._mode = 'encode';
      this._encodeBtn.classList.add('active');
      this._decodeBtn.classList.remove('active');
    });
    this._decodeBtn.addEventListener('click', () => {
      this._mode = 'decode';
      this._decodeBtn.classList.add('active');
      this._encodeBtn.classList.remove('active');
    });

    modeRow.appendChild(this._encodeBtn);
    modeRow.appendChild(this._decodeBtn);

    // Chain mode toggle
    this._chainToggle = PE.el('button', { class: 'btn btn-sm', text: 'Chain Mode: OFF' });
    this._chainMode = false;
    this._chainToggle.addEventListener('click', () => {
      this._chainMode = !this._chainMode;
      this._chainToggle.textContent = `Chain Mode: ${this._chainMode ? 'ON' : 'OFF'}`;
      this._chainToggle.classList.toggle('active', this._chainMode);
    });
    modeRow.appendChild(this._chainToggle);

    // Smart decode button
    const smartBtn = PE.el('button', { class: 'btn btn-sm', text: 'Smart Decode' });
    smartBtn.addEventListener('click', () => this._smartDecode());
    modeRow.appendChild(smartBtn);

    // Auto-detect chain button (server-side recursive decode)
    const autoChainBtn = PE.el('button', { class: 'btn btn-sm', text: 'Auto-Chain' });
    autoChainBtn.addEventListener('click', () => this._autoDetectChain());
    modeRow.appendChild(autoChainBtn);

    // Character inspector button
    const inspectBtn = PE.el('button', { class: 'btn btn-sm', text: 'Inspect Chars' });
    inspectBtn.addEventListener('click', () => this._characterInspector());
    modeRow.appendChild(inspectBtn);

    container.appendChild(modeRow);

    // ── Operation Buttons ──────────────────────────────────────────────────
    const opsCard = PE.el('div', { class: 'panel-card' });
    opsCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Operations' }));

    const opsGrid = PE.el('div', { class: 'decoder-ops-grid' });
    const operations = ['Base64', 'URL', 'Hex', 'HTML', 'JWT', 'Gzip', 'ROT13', 'ASCII85', 'Punycode', 'QP'];

    for (const op of operations) {
      const btn = PE.el('button', { class: 'btn decoder-op-btn', text: op });
      btn.addEventListener('click', () => this._applyOperation(op));
      opsGrid.appendChild(btn);
    }
    opsCard.appendChild(opsGrid);
    container.appendChild(opsCard);

    // ── Output Area ────────────────────────────────────────────────────────
    const outputCard = PE.el('div', { class: 'panel-card' });
    const outputHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    outputHeader.appendChild(PE.el('span', { text: 'Output' }));

    const outputActions = PE.el('div', { class: 'output-actions' });
    const copyBtn = PE.el('button', { class: 'btn btn-xs', text: 'Copy' });
    copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(this._outputArea.value));
    outputActions.appendChild(copyBtn);

    const useAsInputBtn = PE.el('button', { class: 'btn btn-xs', text: 'Use as Input' });
    useAsInputBtn.addEventListener('click', () => {
      this._inputArea.value = this._outputArea.value;
      this._outputArea.value = '';
    });
    outputActions.appendChild(useAsInputBtn);

    outputHeader.appendChild(outputActions);
    outputCard.appendChild(outputHeader);

    this._outputArea = PE.el('textarea', {
      class: 'input decoder-textarea',
      rows: '6',
      readonly: 'true',
      placeholder: 'Output will appear here...',
    });
    outputCard.appendChild(this._outputArea);

    this._outputInfo = PE.el('div', { class: 'decoder-output-info' });
    outputCard.appendChild(this._outputInfo);

    container.appendChild(outputCard);

    // ── History ────────────────────────────────────────────────────────────
    const historyCard = PE.el('div', { class: 'panel-card' });
    const historyHeader = PE.el('div', { class: 'panel-card-title', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } });
    historyHeader.appendChild(PE.el('span', { text: 'Operation History' }));

    const clearHistBtn = PE.el('button', { class: 'btn btn-xs', text: 'Clear History' });
    clearHistBtn.addEventListener('click', () => {
      this._history = [];
      this._renderHistory();
    });
    historyHeader.appendChild(clearHistBtn);

    historyCard.appendChild(historyHeader);

    this._historyList = PE.el('div', { class: 'decoder-history' });
    historyCard.appendChild(this._historyList);
    container.appendChild(historyCard);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('decoder:decode', (text) => {
      if (typeof text === 'string') {
        this._inputArea.value = text;
        this._mode = 'decode';
        this._decodeBtn.classList.add('active');
        this._encodeBtn.classList.remove('active');
      }
    });
  },

  _applyOperation(op) {
    const input = this._chainMode && this._outputArea.value
      ? this._outputArea.value
      : this._inputArea.value;

    if (!input) {
      PE.toast.warning('Enter text to process');
      return;
    }

    let result = '';
    let error = null;
    const direction = this._mode;

    try {
      if (direction === 'encode') {
        result = this._encode(op, input);
      } else {
        result = this._decode(op, input);
      }
    } catch (e) {
      error = e.message;
      PE.toast.error(`${op} ${direction} failed: ${e.message}`);
      return;
    }

    this._outputArea.value = result;
    this._outputInfo.textContent = `${op} ${direction} | Input: ${input.length} chars | Output: ${result.length} chars`;

    // Add to history
    this._history.unshift({
      timestamp: Date.now(),
      operation: op,
      direction,
      inputLength: input.length,
      outputLength: result.length,
      inputPreview: input.slice(0, 60),
      outputPreview: result.slice(0, 60),
    });
    if (this._history.length > 50) this._history.pop();
    this._renderHistory();
  },

  _encode(op, input) {
    switch (op) {
      case 'Base64':
        return btoa(unescape(encodeURIComponent(input)));
      case 'URL':
        return encodeURIComponent(input);
      case 'Hex':
        return Array.from(new TextEncoder().encode(input))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      case 'HTML':
        return input.replace(/[&<>"']/g, ch => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
        })[ch]);
      case 'JWT':
        // JWT encode: treat input as JSON payload, create unsigned token
        try {
          const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' })).replace(/=/g, '');
          const payload = btoa(input).replace(/=/g, '');
          return `${header}.${payload}.`;
        } catch (e) {
          throw new Error('Invalid payload for JWT encoding');
        }
      case 'Gzip':
        throw new Error('Gzip encoding requires server-side processing. Use the API endpoint.');
      case 'ROT13':
        return input.replace(/[a-zA-Z]/g, ch => {
          const base = ch <= 'Z' ? 65 : 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
        });
      case 'ASCII85':
        return this._encodeAscii85(input);
      case 'Punycode':
      case 'QP':
        throw new Error(`${op} encoding requires server-side processing. Use the API.`);
      default:
        throw new Error(`Unknown operation: ${op}`);
    }
  },

  _decode(op, input) {
    switch (op) {
      case 'Base64':
        try {
          return decodeURIComponent(escape(atob(input.trim())));
        } catch (_) {
          return atob(input.trim());
        }
      case 'URL':
        return decodeURIComponent(input);
      case 'Hex': {
        const hex = input.replace(/\s+/g, '').replace(/^0x/i, '');
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
          bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
      case 'HTML': {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = input;
        return textarea.value;
      }
      case 'JWT': {
        const parts = input.trim().split('.');
        if (parts.length < 2) throw new Error('Invalid JWT format');
        const pad = (s) => s + '='.repeat((4 - s.length % 4) % 4);
        const header = JSON.parse(atob(pad(parts[0].replace(/-/g, '+').replace(/_/g, '/'))));
        const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, '+').replace(/_/g, '/'))));
        return JSON.stringify({ header, payload, signature: parts[2] || '' }, null, 2);
      }
      case 'Gzip':
        throw new Error('Gzip decoding requires server-side processing. Use the API endpoint.');
      case 'ROT13':
        // ROT13 is its own inverse
        return input.replace(/[a-zA-Z]/g, ch => {
          const base = ch <= 'Z' ? 65 : 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
        });
      case 'ASCII85':
        return this._decodeAscii85(input);
      case 'Punycode':
      case 'QP':
        throw new Error(`${op} decoding requires server-side processing. Use the API.`);
      default:
        throw new Error(`Unknown operation: ${op}`);
    }
  },

  _encodeAscii85(input) {
    const bytes = new TextEncoder().encode(input);
    let result = '<~';
    for (let i = 0; i < bytes.length; i += 4) {
      let val = 0;
      const chunk = Math.min(4, bytes.length - i);
      for (let j = 0; j < 4; j++) {
        val = val * 256 + (j < chunk ? bytes[i + j] : 0);
      }
      if (val === 0 && chunk === 4) {
        result += 'z';
      } else {
        const chars = [];
        for (let j = 4; j >= 0; j--) {
          chars[j] = String.fromCharCode((val % 85) + 33);
          val = Math.floor(val / 85);
        }
        result += chars.slice(0, chunk + 1).join('');
      }
    }
    result += '~>';
    return result;
  },

  _decodeAscii85(input) {
    let str = input.trim();
    if (str.startsWith('<~')) str = str.slice(2);
    if (str.endsWith('~>')) str = str.slice(0, -2);

    const bytes = [];
    let i = 0;
    while (i < str.length) {
      if (str[i] === 'z') {
        bytes.push(0, 0, 0, 0);
        i++;
        continue;
      }
      const chunk = [];
      for (let j = 0; j < 5 && i < str.length; j++, i++) {
        chunk.push(str.charCodeAt(i) - 33);
      }
      while (chunk.length < 5) chunk.push(84);
      let val = 0;
      for (const c of chunk) val = val * 85 + c;
      const outCount = chunk.length - 1;
      for (let j = 3; j >= 4 - outCount; j--) {
        bytes.push((val >> (j * 8)) & 0xFF);
      }
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  },

  _smartDecode() {
    const input = this._inputArea.value.trim();
    if (!input) {
      PE.toast.warning('Enter text to smart-decode');
      return;
    }

    const results = [];
    let current = input;

    // Try multiple rounds of decoding
    for (let round = 0; round < 5; round++) {
      let decoded = null;
      let method = null;

      // Try Base64
      if (/^[A-Za-z0-9+/=]+$/.test(current) && current.length >= 4) {
        try {
          const d = atob(current.trim());
          if (d.length > 0 && /^[\x20-\x7E\n\r\t]+$/.test(d)) {
            decoded = d;
            method = 'Base64';
          }
        } catch (_) {}
      }

      // Try URL decode
      if (!decoded && (current.includes('%') || current.includes('+'))) {
        try {
          const d = decodeURIComponent(current.replace(/\+/g, ' '));
          if (d !== current) {
            decoded = d;
            method = 'URL';
          }
        } catch (_) {}
      }

      // Try JWT
      if (!decoded && /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(current)) {
        try {
          decoded = this._decode('JWT', current);
          method = 'JWT';
        } catch (_) {}
      }

      // Try Hex
      if (!decoded && /^(0x)?[0-9a-fA-F]+$/.test(current) && current.length >= 4 && current.length % 2 === 0) {
        try {
          const d = this._decode('Hex', current);
          if (/^[\x20-\x7E\n\r\t]+$/.test(d)) {
            decoded = d;
            method = 'Hex';
          }
        } catch (_) {}
      }

      // Try HTML entity decode
      if (!decoded && /&[#a-zA-Z]/.test(current)) {
        try {
          const d = this._decode('HTML', current);
          if (d !== current) {
            decoded = d;
            method = 'HTML';
          }
        } catch (_) {}
      }

      if (decoded && decoded !== current) {
        results.push({ method, output: decoded });
        current = decoded;
      } else {
        break;
      }
    }

    if (results.length > 0) {
      const last = results[results.length - 1];
      this._outputArea.value = last.output;
      const chain = results.map(r => r.method).join(' -> ');
      this._outputInfo.textContent = `Smart decode chain: ${chain}`;
      PE.toast.success(`Decoded via: ${chain}`);
    } else {
      PE.toast.info('No encoding detected');
      this._outputArea.value = input;
      this._outputInfo.textContent = 'No encoding detected';
    }
  },

  async _autoDetectChain() {
    const input = this._inputArea.value.trim();
    if (!input) {
      PE.toast.warning('Enter text to auto-detect');
      return;
    }
    try {
      const result = await PE.api.post('/api/decoder/auto-chain', { text: input });
      if (result.chain && result.chain.length > 0) {
        const last = result.chain[result.chain.length - 1];
        this._outputArea.value = last.decoded;
        const chain = result.chain.map(s => `${s.encoding}(${(s.confidence * 100).toFixed(0)}%)`).join(' → ');
        this._outputInfo.textContent = `Auto-detect chain: ${chain}`;
        PE.toast.success(`Decoded ${result.chain.length} layers: ${chain}`);
      } else {
        PE.toast.info('No encoding layers detected');
        this._outputInfo.textContent = 'No encoding detected';
      }
    } catch (e) {
      // Fallback to local smart decode
      this._smartDecode();
    }
  },

  async _characterInspector() {
    const input = this._inputArea.value;
    if (!input) {
      PE.toast.warning('Enter text to inspect');
      return;
    }
    try {
      const result = await PE.api.post('/api/decoder/inspect', { text: input.slice(0, 500) });
      let html = '<div class="char-inspector"><h4>Character Inspector</h4>';
      html += `<p>Length: ${result.length} | Non-ASCII: ${result.non_ascii_count} | Hidden: ${result.hidden_count}`;
      if (result.has_bom) html += ' | <span style="color:#d32f2f">BOM detected</span>';
      if (result.has_null_bytes) html += ' | <span style="color:#d32f2f">NULL bytes</span>';
      if (result.has_rtl_override) html += ' | <span style="color:#d32f2f">RTL override</span>';
      html += '</p>';
      if (result.homoglyphs && result.homoglyphs.length > 0) {
        html += '<p style="color:#d32f2f">Homoglyphs found: ';
        html += result.homoglyphs.map(h => `"${h.found}" looks like "${h.looks_like}" (${h.codepoint} ${h.script})`).join(', ');
        html += '</p>';
      }
      html += '<table class="meta-table"><tr><th>Char</th><th>Code</th><th>Hex</th><th>Category</th><th>Name</th></tr>';
      for (const ch of (result.characters || []).slice(0, 100)) {
        const cls = ch.hidden ? 'style="background:#fff3e0"' : '';
        html += `<tr ${cls}><td><code>${PE.utils.escapeHtml(ch.char)}</code></td><td>${ch.codepoint}</td><td>${ch.hex}</td><td>${ch.category}</td><td>${PE.utils.escapeHtml(ch.name)}</td></tr>`;
      }
      html += '</table></div>';
      this._outputArea.value = '';
      this._outputInfo.innerHTML = html;
    } catch (e) {
      PE.toast.error('Character inspector requires API. ' + e.message);
    }
  },

  _renderHistory() {
    this._historyList.innerHTML = '';

    if (this._history.length === 0) {
      this._historyList.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: 'No operations yet' })
      ));
      return;
    }

    for (const entry of this._history) {
      const row = PE.el('div', { class: 'decoder-history-item' });
      const time = new Date(entry.timestamp).toLocaleTimeString('en-AU', { hour12: false });
      row.innerHTML = `
        <span class="history-time">${PE.utils.escapeHtml(time)}</span>
        <span class="badge">${PE.utils.escapeHtml(entry.operation)}</span>
        <span class="history-dir">${PE.utils.escapeHtml(entry.direction)}</span>
        <span class="history-preview">${PE.utils.escapeHtml(entry.inputPreview)}</span>
        <span class="history-arrow">&rarr;</span>
        <span class="history-preview">${PE.utils.escapeHtml(entry.outputPreview)}</span>
      `;
      this._historyList.appendChild(row);
    }
  },
};
