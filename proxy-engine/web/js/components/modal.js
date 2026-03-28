/**
 * Modal — Dialog system with backdrop and keyboard handling.
 */
PE.modal = {
  _stack: [],

  show({ title, body, footer, width, onClose }) {
    const backdrop = PE.el('div', { class: 'modal-backdrop' });
    const modal = PE.el('div', { class: 'modal', style: width ? { width } : {} });

    const header = PE.el('div', { class: 'modal-header' });
    header.appendChild(PE.el('h3', { text: title || '' }));
    const closeBtn = PE.el('button', { class: 'close-btn', html: '&times;' });
    closeBtn.addEventListener('click', () => this.close());
    header.appendChild(closeBtn);
    modal.appendChild(header);

    const bodyEl = PE.el('div', { class: 'modal-body' });
    if (typeof body === 'string') bodyEl.innerHTML = body;
    else if (body instanceof HTMLElement) bodyEl.appendChild(body);
    modal.appendChild(bodyEl);

    if (footer) {
      const footerEl = PE.el('div', { class: 'modal-footer' });
      if (typeof footer === 'string') footerEl.innerHTML = footer;
      else if (footer instanceof HTMLElement) footerEl.appendChild(footer);
      else if (Array.isArray(footer)) footer.forEach(el => footerEl.appendChild(el));
      modal.appendChild(footerEl);
    }

    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);

    // Animate in
    requestAnimationFrame(() => backdrop.classList.add('active'));

    const entry = { backdrop, modal, onClose };
    this._stack.push(entry);

    // Escape key
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) this.close();
    });

    return { backdrop, modal, bodyEl, close: () => this.close() };
  },

  confirm({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
    return new Promise((resolve) => {
      const cancelBtn = PE.el('button', { class: 'btn', text: cancelLabel });
      const confirmBtn = PE.el('button', { class: danger ? 'btn btn-danger' : 'btn btn-primary', text: confirmLabel });

      const { close } = this.show({
        title,
        body: PE.el('div', { text: message }),
        footer: [cancelBtn, confirmBtn],
      });

      cancelBtn.addEventListener('click', () => { close(); resolve(false); });
      confirmBtn.addEventListener('click', () => { close(); resolve(true); });
    });
  },

  close() {
    const entry = this._stack.pop();
    if (!entry) return;
    entry.backdrop.classList.remove('active');
    setTimeout(() => entry.backdrop.remove(), 200);
    entry.onClose?.();
  },

  closeAll() {
    while (this._stack.length) this.close();
  },
};
