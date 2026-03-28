/**
 * HexViewer — three-column hex viewer with offset, hex bytes, and ASCII display.
 * Supports click-to-highlight correspondence and editable mode.
 */
class HexViewer {
    constructor(container, options = {}) {
        this.container = typeof container === 'string' ? document.getElementById(container) : container;
        this.data = new Uint8Array(0);
        this.bytesPerRow = options.bytesPerRow || 16;
        this.editable = options.editable || false;
        this.selectedOffset = -1;
        this.onChange = options.onChange || null;
    }

    setData(input) {
        if (typeof input === 'string') {
            this.data = new TextEncoder().encode(input);
        } else if (input instanceof ArrayBuffer) {
            this.data = new Uint8Array(input);
        } else if (input instanceof Uint8Array) {
            this.data = input;
        } else {
            this.data = new Uint8Array(0);
        }
        this.render();
    }

    getData() {
        return this.data;
    }

    getDataAsString() {
        return new TextDecoder().decode(this.data);
    }

    render() {
        if (!this.container) return;

        const rows = [];
        const totalRows = Math.ceil(this.data.length / this.bytesPerRow);

        rows.push('<div class="hex-viewer">');

        // Header row
        rows.push('<div class="hex-header">');
        rows.push('<span class="hex-offset-header">Offset</span>');
        rows.push('<span class="hex-bytes-header">');
        for (let i = 0; i < this.bytesPerRow; i++) {
            rows.push(`<span class="hex-col-header">${i.toString(16).toUpperCase().padStart(2, '0')}</span>`);
        }
        rows.push('</span>');
        rows.push('<span class="hex-ascii-header">ASCII</span>');
        rows.push('</div>');

        // Data rows
        for (let row = 0; row < totalRows; row++) {
            const offset = row * this.bytesPerRow;
            rows.push(`<div class="hex-row" data-offset="${offset}">`);

            // Offset column
            rows.push(`<span class="hex-offset">${offset.toString(16).toUpperCase().padStart(8, '0')}</span>`);

            // Hex bytes column
            rows.push('<span class="hex-bytes">');
            for (let col = 0; col < this.bytesPerRow; col++) {
                const idx = offset + col;
                if (idx < this.data.length) {
                    const byte = this.data[idx];
                    const selected = idx === this.selectedOffset ? ' hex-selected' : '';
                    if (this.editable) {
                        rows.push(`<input class="hex-byte-edit${selected}" data-idx="${idx}" value="${byte.toString(16).toUpperCase().padStart(2, '0')}" maxlength="2" onclick="this.select()" onchange="hexViewerEditByte(this)">`);
                    } else {
                        rows.push(`<span class="hex-byte${selected}" data-idx="${idx}" onclick="hexViewerSelect(${idx})">${byte.toString(16).toUpperCase().padStart(2, '0')}</span>`);
                    }
                } else {
                    rows.push('<span class="hex-byte hex-empty">  </span>');
                }
            }
            rows.push('</span>');

            // ASCII column
            rows.push('<span class="hex-ascii">');
            for (let col = 0; col < this.bytesPerRow; col++) {
                const idx = offset + col;
                if (idx < this.data.length) {
                    const byte = this.data[idx];
                    const ch = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    const selected = idx === this.selectedOffset ? ' hex-selected' : '';
                    const escaped = ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '&' ? '&amp;' : ch === '"' ? '&quot;' : ch;
                    rows.push(`<span class="hex-char${selected}" data-idx="${idx}" onclick="hexViewerSelect(${idx})">${escaped}</span>`);
                }
            }
            rows.push('</span>');
            rows.push('</div>');
        }

        rows.push('</div>');
        rows.push(`<div class="hex-status">Length: ${this.data.length} bytes | ${totalRows} rows</div>`);

        this.container.innerHTML = rows.join('');
    }

    select(offset) {
        this.selectedOffset = offset;
        // Remove old highlights
        this.container.querySelectorAll('.hex-selected').forEach(el => el.classList.remove('hex-selected'));
        // Highlight corresponding hex byte and ASCII char
        this.container.querySelectorAll(`[data-idx="${offset}"]`).forEach(el => el.classList.add('hex-selected'));
    }

    editByte(input) {
        const idx = parseInt(input.dataset.idx);
        const val = parseInt(input.value, 16);
        if (!isNaN(idx) && !isNaN(val) && val >= 0 && val <= 255) {
            this.data[idx] = val;
            // Update ASCII display
            const asciiSpan = this.container.querySelector(`.hex-char[data-idx="${idx}"]`);
            if (asciiSpan) {
                const ch = (val >= 32 && val <= 126) ? String.fromCharCode(val) : '.';
                asciiSpan.textContent = ch;
            }
            if (this.onChange) this.onChange(this.data);
        }
    }
}

// ── Global instance tracking ─────────────────────────────────
window._hexViewers = window._hexViewers || {};

function createHexViewer(containerId, options) {
    const viewer = new HexViewer(containerId, options);
    window._hexViewers[containerId] = viewer;
    return viewer;
}

function hexViewerSelect(idx) {
    for (const viewer of Object.values(window._hexViewers)) {
        viewer.select(idx);
    }
}

function hexViewerEditByte(input) {
    for (const viewer of Object.values(window._hexViewers)) {
        viewer.editByte(input);
    }
}

window.HexViewer = HexViewer;
window.createHexViewer = createHexViewer;

// ── PE.hexViewer compatibility wrapper ───────────────────────
// Maintains backward compatibility with the original PE.hexViewer.render() API
// used by proxy.js detail pane hex tab.
PE.hexViewer = {
    render(container, content) {
        if (!content) {
            container.innerHTML = '<div class="empty-state"><div class="title">No content</div></div>';
            return;
        }
        const viewer = new HexViewer(container, { editable: false });
        viewer.setData(content);
    },

    renderEditable(container, content, onChange) {
        if (!content) {
            container.innerHTML = '<div class="empty-state"><div class="title">No content</div></div>';
            return null;
        }
        const viewer = new HexViewer(container, { editable: true, onChange });
        viewer.setData(content);
        return viewer;
    },

    shouldUseHex(body) {
        return PE.utils.isBinary(body);
    },
};
