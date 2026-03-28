/**
 * SyntaxHighlighter — Regex-based HTTP/JSON/HTML highlighting.
 */
PE.syntax = {
  highlightHTTP(raw) {
    if (!raw) return '';
    const esc = PE.utils.escapeHtml;
    const lines = raw.split('\n');
    const out = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (i === 0) {
        // Request line: METHOD URL VERSION or VERSION STATUS REASON
        const reqMatch = line.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s*(HTTP\/[\d.]+)?$/);
        if (reqMatch) {
          out.push(`<span class="sh-method">${esc(reqMatch[1])}</span> <span class="sh-url">${esc(reqMatch[2])}</span>${reqMatch[3] ? ` <span class="sh-version">${esc(reqMatch[3])}</span>` : ''}`);
          continue;
        }
        const resMatch = line.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/);
        if (resMatch) {
          const code = parseInt(resMatch[2]);
          const cls = code < 300 ? 'sh-status-2xx' : code < 400 ? 'sh-status-3xx' : code < 500 ? 'sh-status-4xx' : 'sh-status-5xx';
          out.push(`<span class="sh-version">${esc(resMatch[1])}</span> <span class="sh-status ${cls}">${esc(resMatch[2])}</span> ${esc(resMatch[3])}`);
          continue;
        }
      }

      // Header line: Name: Value
      const headerMatch = line.match(/^([A-Za-z0-9\-_]+)(\s*:\s*)(.*)$/);
      if (headerMatch && i > 0) {
        out.push(`<span class="sh-header-name">${esc(headerMatch[1])}</span><span class="sh-header-sep">${esc(headerMatch[2])}</span><span class="sh-header-value">${esc(headerMatch[3])}</span>`);
        continue;
      }

      out.push(esc(line));
    }
    return out.join('\n');
  },

  highlightJSON(str) {
    if (!str) return '';
    try {
      // Try to pretty-print first
      const obj = JSON.parse(str);
      str = JSON.stringify(obj, null, 2);
    } catch (_) {}

    return PE.utils.escapeHtml(str).replace(
      /("(?:\\.|[^"\\])*")\s*:/g,
      '<span class="sh-key">$1</span>:'
    ).replace(
      /:\s*("(?:\\.|[^"\\])*")/g,
      ': <span class="sh-string">$1</span>'
    ).replace(
      /:\s*(\d+\.?\d*)/g,
      ': <span class="sh-number">$1</span>'
    ).replace(
      /:\s*(true|false)/g,
      ': <span class="sh-boolean">$1</span>'
    ).replace(
      /:\s*(null)/g,
      ': <span class="sh-null">$1</span>'
    );
  },

  highlightHTML(str) {
    if (!str) return '';
    const esc = PE.utils.escapeHtml(str);
    return esc
      .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="sh-comment">$1</span>')
      .replace(/(&lt;\/?)([\w-]+)/g, '$1<span class="sh-tag">$2</span>')
      .replace(/([\w-]+)(=)(&quot;[^&]*&quot;)/g, '<span class="sh-attr-name">$1</span>$2<span class="sh-attr-value">$3</span>')
      .replace(/(&lt;!DOCTYPE[^&]*&gt;)/gi, '<span class="sh-doctype">$1</span>');
  },

  highlight(content, type) {
    if (!content) return '';
    switch (type) {
      case 'json': return this.highlightJSON(content);
      case 'html': case 'xml': return this.highlightHTML(content);
      case 'http': return this.highlightHTTP(content);
      default: return PE.utils.escapeHtml(content);
    }
  },

  autoDetect(content) {
    if (!content) return 'text';
    const trimmed = content.trimStart();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
    if (trimmed.startsWith('<!') || trimmed.startsWith('<html') || trimmed.startsWith('<?xml')) return 'html';
    if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|HTTP\/)\s/.test(trimmed)) return 'http';
    return 'text';
  },

  renderInto(el, content, type) {
    if (!type) type = this.autoDetect(content);
    el.innerHTML = `<pre class="syntax-hl">${this.highlight(content, type)}</pre>`;
  },

  buildHTTPRequest(flow) {
    if (!flow || !flow.request) return '';
    const req = flow.request;
    const url = new URL(req.url);
    let raw = `${req.method} ${url.pathname}${url.search} ${req.http_version || 'HTTP/1.1'}\n`;
    raw += `Host: ${url.host}\n`;
    if (req.headers) {
      for (const [k, v] of Object.entries(req.headers)) {
        if (k.toLowerCase() === 'host') continue;
        raw += `${k}: ${v}\n`;
      }
    }
    if (req.body) raw += `\n${req.body}`;
    return raw;
  },

  buildHTTPResponse(flow) {
    if (!flow || !flow.response) return '';
    const res = flow.response;
    let raw = `HTTP/1.1 ${res.status_code} ${res.reason || ''}\n`;
    if (res.headers) {
      for (const [k, v] of Object.entries(res.headers)) {
        raw += `${k}: ${v}\n`;
      }
    }
    if (res.body) raw += `\n${res.body}`;
    return raw;
  },
};
