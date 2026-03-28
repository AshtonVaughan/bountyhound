/**
 * ProxyEngine Utilities — escapeHtml, formatBytes, debounce, throttle, etc.
 */

PE.utils = {
  escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  },

  formatBytes(bytes) {
    if (bytes === 0 || bytes == null) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const val = bytes / Math.pow(1024, i);
    return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`;
  },

  formatDuration(ms) {
    if (ms < 1) return '<1ms';
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
  },

  formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('en-AU', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },

  formatDate(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000);
    return d.toLocaleDateString('en-AU') + ' ' + d.toLocaleTimeString('en-AU', { hour12: false });
  },

  relativeTime(ts) {
    const diff = Date.now() / 1000 - ts;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  },

  debounce(fn, delay = 250) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  },

  throttle(fn, limit = 100) {
    let inThrottle = false;
    let lastArgs = null;
    return function(...args) {
      if (!inThrottle) {
        fn.apply(this, args);
        inThrottle = true;
        setTimeout(() => {
          inThrottle = false;
          if (lastArgs) { fn.apply(this, lastArgs); lastArgs = null; }
        }, limit);
      } else {
        lastArgs = args;
      }
    };
  },

  truncate(str, max = 100) {
    if (!str || str.length <= max) return str || '';
    return str.slice(0, max) + '...';
  },

  copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(
      () => PE.toast?.success('Copied to clipboard'),
      () => PE.toast?.error('Copy failed'),
    );
  },

  statusClass(code) {
    if (!code) return '';
    if (code < 300) return 'status-2xx';
    if (code < 400) return 'status-3xx';
    if (code < 500) return 'status-4xx';
    return 'status-5xx';
  },

  methodClass(method) {
    return `method-${(method || 'GET').toUpperCase()}`;
  },

  sevClass(severity) {
    return `sev-${(severity || 'info').toLowerCase()}`;
  },

  sevOrder(severity) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return order[(severity || 'info').toLowerCase()] ?? 5;
  },

  genId() {
    return Math.random().toString(36).substr(2, 9);
  },

  parseContentType(ct) {
    if (!ct) return 'unknown';
    ct = ct.toLowerCase();
    if (ct.includes('json')) return 'json';
    if (ct.includes('html')) return 'html';
    if (ct.includes('xml')) return 'xml';
    if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
    if (ct.includes('css')) return 'css';
    if (ct.includes('image/')) return 'image';
    if (ct.includes('font/') || ct.includes('woff')) return 'font';
    if (ct.includes('text/')) return 'text';
    return 'binary';
  },

  isBinary(body) {
    if (!body) return false;
    if (body.startsWith('<binary ')) return true;
    // Check for non-printable characters
    for (let i = 0; i < Math.min(body.length, 512); i++) {
      const c = body.charCodeAt(i);
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) return true;
    }
    return false;
  },

  buildCurl(method, url, headers, body) {
    let cmd = `curl -X ${method}`;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        cmd += ` -H '${k}: ${v}'`;
      }
    }
    if (body) cmd += ` -d '${body.replace(/'/g, "'\\''")}'`;
    cmd += ` '${url}'`;
    return cmd;
  },

  buildPython(method, url, headers, body) {
    let code = 'import requests\n\n';
    code += `resp = requests.${method.toLowerCase()}(\n`;
    code += `    '${url}',\n`;
    if (headers && Object.keys(headers).length) {
      code += `    headers=${JSON.stringify(headers, null, 4)},\n`;
    }
    if (body) code += `    data='${body}',\n`;
    code += ')\nprint(resp.status_code, resp.text[:500])\n';
    return code;
  },
};
