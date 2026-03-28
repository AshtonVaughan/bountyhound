/**
 * WebSocket Panel — WS message viewer with intercept queue and custom message sending.
 */
PE.panels = PE.panels || {};

PE.panels.websocket = {
  _container: null,
  _table: null,
  _messages: [],
  _filterFlowId: '',
  _interceptEnabled: false,
  _interceptQueue: [],

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('websocket-panel');

    // ── Toolbar ────────────────────────────────────────────────────────────
    const toolbar = PE.el('div', { class: 'panel-toolbar' });

    // Filter by flow_id
    toolbar.appendChild(PE.el('label', { class: 'toolbar-label', text: 'Flow ID:' }));
    this._flowFilterInput = PE.el('input', { class: 'input input-sm', type: 'text', placeholder: 'Filter by flow ID', style: { width: '120px' } });
    this._flowFilterInput.addEventListener('input', PE.utils.debounce(() => {
      this._filterFlowId = this._flowFilterInput.value.trim();
      this._applyFilter();
    }, 300));
    toolbar.appendChild(this._flowFilterInput);

    // Toggle WS intercept
    this._interceptBtn = PE.el('button', { class: 'btn btn-sm', text: 'Intercept: OFF' });
    this._interceptBtn.addEventListener('click', () => this._toggleIntercept());
    toolbar.appendChild(this._interceptBtn);

    // Clear messages
    const clearBtn = PE.el('button', { class: 'btn btn-sm', text: 'Clear' });
    clearBtn.addEventListener('click', () => {
      this._messages = [];
      this._table.setData([]);
      this._detailPane.innerHTML = '';
    });
    toolbar.appendChild(clearBtn);

    // Count label
    this._countLabel = PE.el('span', { class: 'toolbar-count', text: '0 messages' });
    toolbar.appendChild(this._countLabel);

    container.appendChild(toolbar);

    // ── Main content: split between messages and detail/intercept ────────
    const mainArea = PE.el('div', { class: 'ws-main-area' });

    // Left: message table
    const tableWrap = PE.el('div', { class: 'ws-table-wrap' });

    this._table = new PE.VirtualTable(tableWrap, {
      columns: [
        {
          key: 'timestamp', label: 'Time', width: '90px', sortable: true,
          render: (val) => PE.utils.formatTime(val),
        },
        {
          key: 'direction', label: 'Dir', width: '50px',
          render: (val) => {
            if (val === 'send' || val === 'outgoing') return '<span class="ws-dir ws-send" title="Sent">\u2191</span>';
            return '<span class="ws-dir ws-recv" title="Received">\u2193</span>';
          },
        },
        {
          key: 'content', label: 'Content', flex: '2',
          render: (val) => `<span class="ws-content-preview">${PE.utils.escapeHtml(PE.utils.truncate(val, 100))}</span>`,
        },
        { key: 'length', label: 'Length', width: '70px', sortable: true },
        {
          key: 'flow_id', label: 'Flow', width: '90px',
          render: (val) => `<span class="ws-flow-id">${PE.utils.escapeHtml(PE.utils.truncate(val, 12))}</span>`,
        },
        {
          key: 'opcode', label: 'Type', width: '70px',
          render: (val) => {
            const types = { 1: 'Text', 2: 'Binary', 8: 'Close', 9: 'Ping', 10: 'Pong' };
            return PE.utils.escapeHtml(types[val] || val || 'Text');
          },
        },
      ],
      onRowClick: (row) => this._showDetail(row),
      getId: (row) => row.id || row.message_id || PE.utils.genId(),
    });

    mainArea.appendChild(tableWrap);

    // Right: detail + intercept + send
    const sidePane = PE.el('div', { class: 'ws-side-pane' });

    // Detail view
    this._detailPane = PE.el('div', { class: 'ws-detail' });
    this._detailPane.appendChild(PE.el('div', { class: 'empty-state' },
      PE.el('div', { class: 'title', text: 'Select a message to view details' })
    ));
    sidePane.appendChild(this._detailPane);

    // Intercept queue
    const interceptCard = PE.el('div', { class: 'panel-card ws-intercept-card' });
    interceptCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Intercept Queue' }));
    this._interceptQueue_el = PE.el('div', { class: 'ws-intercept-queue' });
    interceptCard.appendChild(this._interceptQueue_el);

    const interceptBtns = PE.el('div', { class: 'form-actions' });
    const forwardBtn = PE.el('button', { class: 'btn btn-sm btn-primary', text: 'Forward' });
    forwardBtn.addEventListener('click', () => this._forwardIntercepted());
    interceptBtns.appendChild(forwardBtn);

    const forwardAllBtn = PE.el('button', { class: 'btn btn-sm', text: 'Forward All' });
    forwardAllBtn.addEventListener('click', () => this._forwardAllIntercepted());
    interceptBtns.appendChild(forwardAllBtn);

    const dropBtn = PE.el('button', { class: 'btn btn-sm btn-danger', text: 'Drop' });
    dropBtn.addEventListener('click', () => this._dropIntercepted());
    interceptBtns.appendChild(dropBtn);

    interceptCard.appendChild(interceptBtns);
    sidePane.appendChild(interceptCard);

    // Send custom message
    const sendCard = PE.el('div', { class: 'panel-card ws-send-card' });
    sendCard.appendChild(PE.el('div', { class: 'panel-card-title', text: 'Send Custom Message' }));

    const sendForm = PE.el('div', { class: 'form-grid' });

    sendForm.appendChild(PE.el('label', { class: 'form-label', text: 'Flow ID' }));
    this._sendFlowId = PE.el('input', { class: 'input', type: 'text', placeholder: 'Target flow ID' });
    sendForm.appendChild(this._sendFlowId);

    sendForm.appendChild(PE.el('label', { class: 'form-label', text: 'Message' }));
    this._sendContent = PE.el('textarea', { class: 'input', rows: '4', placeholder: 'Message content...' });
    sendForm.appendChild(this._sendContent);

    sendCard.appendChild(sendForm);

    const sendBtns = PE.el('div', { class: 'form-actions' });
    const sendBtn = PE.el('button', { class: 'btn btn-primary', text: 'Send' });
    sendBtn.addEventListener('click', () => this._sendMessage());
    sendBtns.appendChild(sendBtn);

    sendCard.appendChild(sendBtns);
    sidePane.appendChild(sendCard);

    mainArea.appendChild(sidePane);
    container.appendChild(mainArea);

    // ── Events ─────────────────────────────────────────────────────────────
    PE.bus.on('ws:message', (msg) => {
      if (msg) {
        msg.id = msg.id || msg.message_id || PE.utils.genId();
        msg.length = msg.length || (msg.content ? msg.content.length : 0);
        this._messages.push(msg);
        this._applyFilter();
      }
    });

    PE.bus.on('intercept:new', (data) => {
      if (data && data.type === 'websocket') {
        this._interceptQueue.push(data);
        this._renderInterceptQueue();
      }
    });

    PE.bus.on('panel:activated', (id) => {
      if (id === 'websocket') this.refresh();
    });

    this.refresh();
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/websocket/messages');
      const messages = Array.isArray(data) ? data : (data.messages || []);
      this._messages = messages.map(m => ({
        ...m,
        id: m.id || m.message_id || PE.utils.genId(),
        length: m.length || (m.content ? m.content.length : 0),
      }));
      this._applyFilter();
    } catch (e) {
      console.error('[websocket] refresh failed:', e);
    }
  },

  _applyFilter() {
    let filtered = this._messages;

    if (this._filterFlowId) {
      filtered = filtered.filter(m => (m.flow_id || '').includes(this._filterFlowId));
    }

    this._table.setData(filtered);
    this._countLabel.textContent = `${filtered.length} messages`;
  },

  _showDetail(msg) {
    if (!msg) return;

    const esc = PE.utils.escapeHtml;
    const dirLabel = (msg.direction === 'send' || msg.direction === 'outgoing') ? 'Sent' : 'Received';
    const dirIcon = dirLabel === 'Sent' ? '\u2191' : '\u2193';

    this._detailPane.innerHTML = `
      <div class="detail-header">
        <span class="ws-dir ${dirLabel === 'Sent' ? 'ws-send' : 'ws-recv'}">${dirIcon} ${esc(dirLabel)}</span>
        <span class="detail-time">${PE.utils.formatDate(msg.timestamp)}</span>
      </div>
      <div class="detail-section">
        <div class="detail-label">Flow ID</div>
        <div class="detail-value">${esc(msg.flow_id || '')}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Length</div>
        <div class="detail-value">${msg.length || 0} bytes</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Content</div>
        <pre class="ws-detail-content">${esc(msg.content || '')}</pre>
      </div>
    `;

    // Try JSON highlighting
    const contentEl = this._detailPane.querySelector('.ws-detail-content');
    if (contentEl && msg.content) {
      const type = PE.syntax.autoDetect(msg.content);
      if (type !== 'text') {
        contentEl.innerHTML = PE.syntax.highlight(msg.content, type);
      }
    }

    // Copy button
    const copyBtn = PE.el('button', { class: 'btn btn-xs', text: 'Copy Content', style: { marginTop: '8px' } });
    copyBtn.addEventListener('click', () => PE.utils.copyToClipboard(msg.content || ''));
    this._detailPane.appendChild(copyBtn);

    // Pre-fill send form with this flow ID
    if (msg.flow_id) {
      this._sendFlowId.value = msg.flow_id;
    }
  },

  async _toggleIntercept() {
    try {
      const result = await PE.api.post('/api/websocket/intercept/toggle');
      this._interceptEnabled = result.enabled !== false;
      this._interceptBtn.textContent = `Intercept: ${this._interceptEnabled ? 'ON' : 'OFF'}`;
      this._interceptBtn.classList.toggle('active', this._interceptEnabled);
      PE.toast.info(`WS intercept ${this._interceptEnabled ? 'enabled' : 'disabled'}`);
    } catch (e) {
      PE.toast.error('Failed to toggle WS intercept: ' + e.message);
    }
  },

  _renderInterceptQueue() {
    this._interceptQueue_el.innerHTML = '';

    if (this._interceptQueue.length === 0) {
      this._interceptQueue_el.appendChild(PE.el('div', { class: 'empty-state' },
        PE.el('div', { class: 'title', text: 'No intercepted messages' })
      ));
      return;
    }

    for (let i = 0; i < this._interceptQueue.length; i++) {
      const msg = this._interceptQueue[i];
      const item = PE.el('div', { class: `ws-intercept-item ${i === 0 ? 'active' : ''}` });
      item.innerHTML = `
        <span class="ws-dir ${msg.direction === 'send' ? 'ws-send' : 'ws-recv'}">${msg.direction === 'send' ? '\u2191' : '\u2193'}</span>
        <span class="ws-content-preview">${PE.utils.escapeHtml(PE.utils.truncate(msg.content || '', 50))}</span>
        <span class="ws-flow-id">${PE.utils.escapeHtml(msg.flow_id || '')}</span>
      `;

      // Allow editing intercepted content
      if (i === 0) {
        const editArea = PE.el('textarea', { class: 'input ws-intercept-edit', rows: '3' });
        editArea.value = msg.content || '';
        editArea.addEventListener('input', () => {
          this._interceptQueue[0]._editedContent = editArea.value;
        });
        item.appendChild(editArea);
      }

      this._interceptQueue_el.appendChild(item);
    }
  },

  async _forwardIntercepted() {
    if (this._interceptQueue.length === 0) {
      PE.toast.warning('No intercepted messages to forward');
      return;
    }

    const msg = this._interceptQueue[0];
    const content = msg._editedContent !== undefined ? msg._editedContent : msg.content;

    try {
      await PE.api.post('/api/websocket/intercept/forward', {
        intercept_id: msg.intercept_id || msg.id,
        content,
      });
      this._interceptQueue.shift();
      this._renderInterceptQueue();
      PE.toast.success('Message forwarded');
    } catch (e) {
      PE.toast.error('Failed to forward: ' + e.message);
    }
  },

  async _forwardAllIntercepted() {
    if (this._interceptQueue.length === 0) return;

    try {
      for (const msg of this._interceptQueue) {
        await PE.api.post('/api/websocket/intercept/forward', {
          intercept_id: msg.intercept_id || msg.id,
          content: msg.content,
        });
      }
      this._interceptQueue = [];
      this._renderInterceptQueue();
      PE.toast.success('All messages forwarded');
    } catch (e) {
      PE.toast.error('Failed to forward all: ' + e.message);
    }
  },

  async _dropIntercepted() {
    if (this._interceptQueue.length === 0) {
      PE.toast.warning('No intercepted messages to drop');
      return;
    }

    const msg = this._interceptQueue[0];
    try {
      await PE.api.post('/api/websocket/intercept/drop', {
        intercept_id: msg.intercept_id || msg.id,
      });
      this._interceptQueue.shift();
      this._renderInterceptQueue();
      PE.toast.success('Message dropped');
    } catch (e) {
      PE.toast.error('Failed to drop: ' + e.message);
    }
  },

  async _sendMessage() {
    const flowId = this._sendFlowId.value.trim();
    const content = this._sendContent.value;

    if (!flowId) {
      PE.toast.warning('Enter a flow ID');
      return;
    }
    if (!content) {
      PE.toast.warning('Enter message content');
      return;
    }

    try {
      await PE.api.post('/api/websocket/send', { flow_id: flowId, content });
      PE.toast.success('Message sent');
      this._sendContent.value = '';
    } catch (e) {
      PE.toast.error('Failed to send message: ' + e.message);
    }
  },
};
