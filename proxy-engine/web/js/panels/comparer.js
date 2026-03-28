/**
 * Comparer Panel — Side-by-side diff with syntax highlighting and multiple diff modes.
 */
PE.panels = PE.panels || {};

PE.panels.comparer = {
  _container: null,

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('comparer-panel');

    // ── Toolbar ────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar' });

    // Diff mode selector
    toolbar.appendChild(PE.el('label', { class: 'toolbar-label', text: 'Mode:' }));
    this._modeSelect = PE.el('select', { class: 'input input-sm' });
    for (const mode of ['line', 'word', 'char', 'json', 'html']) {
      this._modeSelect.appendChild(PE.el('option', { value: mode, text: mode.charAt(0).toUpperCase() + mode.slice(1) }));
    }
    toolbar.appendChild(this._modeSelect);

    // Load from flow IDs
    toolbar.appendChild(PE.el('label', { class: 'toolbar-label', text: 'Flow Left:' }));
    this._flowLeftInput = PE.el('input', { class: 'input input-sm', type: 'text', placeholder: 'Flow ID', style: { width: '100px' } });
    toolbar.appendChild(this._flowLeftInput);

    toolbar.appendChild(PE.el('label', { class: 'toolbar-label', text: 'Flow Right:' }));
    this._flowRightInput = PE.el('input', { class: 'input input-sm', type: 'text', placeholder: 'Flow ID', style: { width: '100px' } });
    toolbar.appendChild(this._flowRightInput);

    const loadFlowsBtn = PE.el('button', { class: 'btn btn-sm', text: 'Load Flows' });
    loadFlowsBtn.addEventListener('click', () => this._loadFlows());
    toolbar.appendChild(loadFlowsBtn);

    // Compare button
    const compareBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Compare' });
    compareBtn.addEventListener('click', () => this._compare());
    toolbar.appendChild(compareBtn);

    // Swap button
    const swapBtn = PE.el('button', { class: 'btn btn-sm', text: 'Swap' });
    swapBtn.addEventListener('click', () => this._swap());
    toolbar.appendChild(swapBtn);

    // Clear button
    const clearBtn = PE.el('button', { class: 'btn btn-sm', text: 'Clear' });
    clearBtn.addEventListener('click', () => this._clear());
    toolbar.appendChild(clearBtn);

    container.appendChild(toolbar);

    // ── Input Area — Two panes side-by-side ─────────────────────────────
    const inputArea = PE.el('div', { class: 'comparer-input-area' });

    // Left pane
    const leftPane = PE.el('div', { class: 'comparer-pane' });
    leftPane.appendChild(PE.el('div', { class: 'comparer-pane-title', text: 'Left' }));
    this._leftText = PE.el('textarea', {
      class: 'input comparer-textarea',
      placeholder: 'Paste content or load from flow...',
    });
    leftPane.appendChild(this._leftText);
    inputArea.appendChild(leftPane);

    // Right pane
    const rightPane = PE.el('div', { class: 'comparer-pane' });
    rightPane.appendChild(PE.el('div', { class: 'comparer-pane-title', text: 'Right' }));
    this._rightText = PE.el('textarea', {
      class: 'input comparer-textarea',
      placeholder: 'Paste content or load from flow...',
    });
    rightPane.appendChild(this._rightText);
    inputArea.appendChild(rightPane);

    container.appendChild(inputArea);

    // Synchronized scrolling
    let syncing = false;
    this._leftText.addEventListener('scroll', () => {
      if (syncing) return;
      syncing = true;
      this._rightText.scrollTop = this._leftText.scrollTop;
      this._rightText.scrollLeft = this._leftText.scrollLeft;
      syncing = false;
    });
    this._rightText.addEventListener('scroll', () => {
      if (syncing) return;
      syncing = true;
      this._leftText.scrollTop = this._rightText.scrollTop;
      this._leftText.scrollLeft = this._rightText.scrollLeft;
      syncing = false;
    });

    // ── Diff Output ────────────────────────────────────────────────────────
    this._diffOutput = PE.el('div', { class: 'comparer-diff-output' });
    this._diffOutput.appendChild(PE.el('div', { class: 'empty-state' },
      PE.el('div', { class: 'title', text: 'Enter content and click Compare to see differences' })
    ));
    container.appendChild(this._diffOutput);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('comparer:loadLeft', (content) => {
      if (typeof content === 'string') this._leftText.value = content;
    });
    PE.bus.on('comparer:loadRight', (content) => {
      if (typeof content === 'string') this._rightText.value = content;
    });
    PE.bus.on('comparer:loadFlows', (data) => {
      if (data.left) this._flowLeftInput.value = data.left;
      if (data.right) this._flowRightInput.value = data.right;
      this._loadFlows();
    });
  },

  async _loadFlows() {
    const leftId = this._flowLeftInput.value.trim();
    const rightId = this._flowRightInput.value.trim();

    if (!leftId && !rightId) {
      PE.toast.warning('Enter at least one flow ID');
      return;
    }

    try {
      if (leftId) {
        const flow = await PE.api.get(`/api/flows/${leftId}`);
        this._leftText.value = this._flowToText(flow);
      }
      if (rightId) {
        const flow = await PE.api.get(`/api/flows/${rightId}`);
        this._rightText.value = this._flowToText(flow);
      }
      PE.toast.info('Flows loaded');
    } catch (e) {
      PE.toast.error('Failed to load flows: ' + e.message);
    }
  },

  _flowToText(flow) {
    let text = '';
    if (flow.request) {
      text += PE.syntax.buildHTTPRequest(flow);
    }
    if (flow.response) {
      text += '\n\n--- Response ---\n\n';
      text += PE.syntax.buildHTTPResponse(flow);
    }
    return text;
  },

  async _compare() {
    const left = this._leftText.value;
    const right = this._rightText.value;

    if (!left && !right) {
      PE.toast.warning('Enter content to compare');
      return;
    }

    const mode = this._modeSelect.value;

    // Build request payload
    const payload = { left_content: left, right_content: right, diff_mode: mode };
    // If flow IDs are set, also send them for timing comparison
    const leftId = this._flowLeftInput.value.trim();
    const rightId = this._flowRightInput.value.trim();
    if (leftId) payload.left_flow_id = leftId;
    if (rightId) payload.right_flow_id = rightId;

    try {
      const result = await PE.api.post('/api/comparer/diff', payload);
      this._renderDiff(result);

      // If both flow IDs provided, also fetch timing comparison
      if (leftId && rightId) {
        try {
          const timing = await PE.api.post('/api/comparer/timing', {
            left_flow_id: leftId, right_flow_id: rightId
          });
          if (timing && !timing.error) this._renderTiming(timing);
        } catch (_) { /* timing endpoint optional */ }
      }
    } catch (e) {
      // Fall back to local diff if API is unavailable
      this._renderLocalDiff(left, right, mode);
    }
  },

  _renderTiming(timing) {
    const el = PE.el('div', { class: 'comparer-timing' });
    el.innerHTML = `
      <h4>Response Timing Comparison</h4>
      <table class="meta-table">
        <tr><td></td><td><strong>Left</strong></td><td><strong>Right</strong></td><td><strong>Diff</strong></td></tr>
        <tr><td>Status</td><td>${timing.left?.status || '?'}</td><td>${timing.right?.status || '?'}</td><td>—</td></tr>
        <tr><td>Duration</td><td>${timing.left?.duration_ms?.toFixed(1) || '?'} ms</td><td>${timing.right?.duration_ms?.toFixed(1) || '?'} ms</td><td>${timing.diff_ms?.toFixed(1) || '?'} ms</td></tr>
        <tr><td>Size</td><td>${timing.left?.size_bytes || '?'} B</td><td>${timing.right?.size_bytes || '?'} B</td><td>${timing.diff_size || '?'} B</td></tr>
        <tr><td>Ratio</td><td colspan="3">${timing.timing_ratio?.toFixed(2) || '?'}x ${timing.timing_anomaly ? '<span style="color:#d32f2f">⚠ ANOMALY</span>' : ''}</td></tr>
      </table>
      ${timing.note ? `<p style="color:#d32f2f;margin-top:8px">${PE.utils.escapeHtml(timing.note)}</p>` : ''}
    `;
    this._diffOutput.appendChild(el);
  },

  _renderDiff(result) {
    this._diffOutput.innerHTML = '';

    if (result.identical) {
      this._diffOutput.appendChild(PE.el('div', { class: 'comparer-identical', text: 'Content is identical' }));
      return;
    }

    const statsBar = PE.el('div', { class: 'comparer-stats' });
    statsBar.innerHTML = `
      <span class="diff-stat diff-added">+${result.additions || 0} added</span>
      <span class="diff-stat diff-removed">-${result.deletions || 0} removed</span>
      <span class="diff-stat diff-unchanged">${result.unchanged || 0} unchanged</span>
    `;
    this._diffOutput.appendChild(statsBar);

    const diffContent = PE.el('div', { class: 'comparer-diff-content' });

    if (result.hunks) {
      for (const hunk of result.hunks) {
        this._renderHunk(diffContent, hunk);
      }
    } else if (result.lines) {
      this._renderLines(diffContent, result.lines);
    } else if (result.diff_text) {
      diffContent.appendChild(PE.el('pre', { class: 'diff-pre', html: this._colorizeDiffText(result.diff_text) }));
    }

    this._diffOutput.appendChild(diffContent);
  },

  _renderHunk(parent, hunk) {
    if (hunk.header) {
      parent.appendChild(PE.el('div', { class: 'diff-hunk-header', text: hunk.header }));
    }
    if (hunk.lines) {
      this._renderLines(parent, hunk.lines);
    }
  },

  _renderLines(parent, lines) {
    for (const line of lines) {
      const cls = line.type === 'add' ? 'diff-line-added'
        : line.type === 'remove' ? 'diff-line-removed'
        : 'diff-line-context';
      const prefix = line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' ';
      const lineEl = PE.el('div', { class: `diff-line ${cls}` });

      if (line.left_num != null) {
        lineEl.appendChild(PE.el('span', { class: 'diff-line-num', text: String(line.left_num) }));
      } else {
        lineEl.appendChild(PE.el('span', { class: 'diff-line-num', text: '' }));
      }
      if (line.right_num != null) {
        lineEl.appendChild(PE.el('span', { class: 'diff-line-num', text: String(line.right_num) }));
      } else {
        lineEl.appendChild(PE.el('span', { class: 'diff-line-num', text: '' }));
      }
      lineEl.appendChild(PE.el('span', { class: 'diff-line-prefix', text: prefix }));
      lineEl.appendChild(PE.el('span', { class: 'diff-line-content', text: line.content || line.text || '' }));

      parent.appendChild(lineEl);
    }
  },

  _renderLocalDiff(left, right, mode) {
    this._diffOutput.innerHTML = '';

    const leftLines = left.split('\n');
    const rightLines = right.split('\n');

    if (left === right) {
      this._diffOutput.appendChild(PE.el('div', { class: 'comparer-identical', text: 'Content is identical' }));
      return;
    }

    let additions = 0;
    let deletions = 0;
    let unchanged = 0;

    const diffContent = PE.el('div', { class: 'comparer-diff-content' });
    const maxLen = Math.max(leftLines.length, rightLines.length);

    if (mode === 'json') {
      // Attempt to pretty-print both sides for better comparison
      try {
        const leftObj = JSON.parse(left);
        const rightObj = JSON.parse(right);
        const leftPretty = JSON.stringify(leftObj, null, 2).split('\n');
        const rightPretty = JSON.stringify(rightObj, null, 2).split('\n');
        this._diffLineSets(diffContent, leftPretty, rightPretty);
      } catch (_) {
        this._diffLineSets(diffContent, leftLines, rightLines);
      }
    } else {
      this._diffLineSets(diffContent, leftLines, rightLines);
    }

    this._diffOutput.appendChild(diffContent);
  },

  _diffLineSets(parent, leftLines, rightLines) {
    const maxLen = Math.max(leftLines.length, rightLines.length);
    let additions = 0;
    let deletions = 0;
    let unchanged = 0;

    const lines = [];
    for (let i = 0; i < maxLen; i++) {
      const l = i < leftLines.length ? leftLines[i] : undefined;
      const r = i < rightLines.length ? rightLines[i] : undefined;

      if (l === r) {
        unchanged++;
        lines.push({ type: 'context', content: l, left_num: i + 1, right_num: i + 1 });
      } else {
        if (l !== undefined) {
          deletions++;
          lines.push({ type: 'remove', content: l, left_num: i + 1, right_num: null });
        }
        if (r !== undefined) {
          additions++;
          lines.push({ type: 'add', content: r, left_num: null, right_num: i + 1 });
        }
      }
    }

    const statsBar = PE.el('div', { class: 'comparer-stats' });
    statsBar.innerHTML = `
      <span class="diff-stat diff-added">+${additions} added</span>
      <span class="diff-stat diff-removed">-${deletions} removed</span>
      <span class="diff-stat diff-unchanged">${unchanged} unchanged</span>
    `;
    parent.parentElement?.insertBefore(statsBar, parent);

    this._renderLines(parent, lines);
  },

  _colorizeDiffText(text) {
    const esc = PE.utils.escapeHtml;
    return text.split('\n').map(line => {
      if (line.startsWith('+')) return `<span class="diff-line-added">${esc(line)}</span>`;
      if (line.startsWith('-')) return `<span class="diff-line-removed">${esc(line)}</span>`;
      if (line.startsWith('@')) return `<span class="diff-hunk-header">${esc(line)}</span>`;
      return esc(line);
    }).join('\n');
  },

  _swap() {
    const tmp = this._leftText.value;
    this._leftText.value = this._rightText.value;
    this._rightText.value = tmp;

    const tmpId = this._flowLeftInput.value;
    this._flowLeftInput.value = this._flowRightInput.value;
    this._flowRightInput.value = tmpId;
  },

  _clear() {
    this._leftText.value = '';
    this._rightText.value = '';
    this._flowLeftInput.value = '';
    this._flowRightInput.value = '';
    this._diffOutput.innerHTML = '';
    this._diffOutput.appendChild(PE.el('div', { class: 'empty-state' },
      PE.el('div', { class: 'title', text: 'Enter content and click Compare to see differences' })
    ));
  },
};
