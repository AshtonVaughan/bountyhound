/**
 * Toast — Notification system.
 */
PE.toast = {
  _container: null,

  _getContainer() {
    if (!this._container) {
      this._container = PE.el('div', { class: 'toast-container' });
      document.body.appendChild(this._container);
    }
    return this._container;
  },

  show(message, type = 'info', duration = 3000) {
    const toast = PE.el('div', { class: `toast ${type}` });
    toast.textContent = message;
    this._getContainer().appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 200);
    }, duration);
    return toast;
  },

  success(msg, dur) { return this.show(msg, 'success', dur); },
  error(msg, dur) { return this.show(msg, 'error', dur || 5000); },
  warning(msg, dur) { return this.show(msg, 'warning', dur || 4000); },
  info(msg, dur) { return this.show(msg, 'info', dur); },
};
