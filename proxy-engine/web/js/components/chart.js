/**
 * Chart — Pure SVG charts: donut, bar, sparkline.
 */
PE.chart = {
  donut(container, data, { size = 120, thickness = 20, label = '' } = {}) {
    const total = data.reduce((s, d) => s + d.value, 0);
    if (!total) { container.innerHTML = ''; return; }
    const cx = size / 2, cy = size / 2, r = (size - thickness) / 2;
    let angle = -90;
    const paths = [];

    for (const d of data) {
      const pct = d.value / total;
      const a1 = angle * Math.PI / 180;
      const sweep = pct * 360;
      const a2 = (angle + sweep) * Math.PI / 180;
      const large = sweep > 180 ? 1 : 0;
      const x1 = cx + r * Math.cos(a1);
      const y1 = cy + r * Math.sin(a1);
      const x2 = cx + r * Math.cos(a2);
      const y2 = cy + r * Math.sin(a2);
      paths.push(`<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2}" fill="none" stroke="${d.color}" stroke-width="${thickness}" />`);
      angle += sweep;
    }

    container.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      ${paths.join('')}
      <text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="central" fill="var(--text)" font-size="18" font-weight="700">${total}</text>
      ${label ? `<text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="var(--text-dim)" font-size="10">${label}</text>` : ''}
    </svg>`;
  },

  bar(container, data, { width = 300, height = 120, barWidth = 20 } = {}) {
    if (!data.length) { container.innerHTML = ''; return; }
    const max = Math.max(...data.map(d => d.value), 1);
    const gap = Math.max(2, (width - data.length * barWidth) / (data.length + 1));
    const bars = [];

    data.forEach((d, i) => {
      const x = gap + i * (barWidth + gap);
      const h = (d.value / max) * (height - 24);
      const y = height - 20 - h;
      bars.push(`<rect x="${x}" y="${y}" width="${barWidth}" height="${h}" fill="${d.color || 'var(--accent)'}" rx="2" />`);
      bars.push(`<text x="${x + barWidth / 2}" y="${height - 6}" text-anchor="middle" fill="var(--text-dim)" font-size="9">${d.label || ''}</text>`);
      if (d.value > 0) {
        bars.push(`<text x="${x + barWidth / 2}" y="${y - 4}" text-anchor="middle" fill="var(--text-dim)" font-size="9">${d.value}</text>`);
      }
    });

    container.innerHTML = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${bars.join('')}</svg>`;
  },

  sparkline(container, values, { width = 200, height = 40, color = 'var(--accent)', fill = true } = {}) {
    if (!values.length) { container.innerHTML = ''; return; }
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const range = max - min || 1;
    const step = width / Math.max(values.length - 1, 1);

    const points = values.map((v, i) => `${i * step},${height - ((v - min) / range) * (height - 4) - 2}`);
    const path = `M${points.join(' L')}`;

    let fillPath = '';
    if (fill) {
      fillPath = `<path d="${path} L${width},${height} L0,${height} Z" fill="${color}" opacity="0.1" />`;
    }

    container.innerHTML = `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
      ${fillPath}
      <path d="${path}" fill="none" stroke="${color}" stroke-width="1.5" />
    </svg>`;
  },
};
