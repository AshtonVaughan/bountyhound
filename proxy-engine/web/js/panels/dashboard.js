/**
 * Dashboard Panel — Severity donut chart, flow sparkline, scan progress, top hosts.
 */
PE.panels = PE.panels || {};

PE.panels.dashboard = {
  _interval: null,
  _container: null,
  _els: {},

  init(container) {
    this._container = container;
    container.innerHTML = '';
    container.classList.add('dashboard-panel');

    // ── Stat cards row ──────────────────────────────────────────────────────
    const statsRow = PE.el('div', { class: 'dash-stats-row' });

    this._els.totalFlows = this._createStatCard(statsRow, 'Total Flows', '0', 'stat-flows');
    this._els.activeScans = this._createStatCard(statsRow, 'Active Scans', '0', 'stat-scans');
    this._els.totalFindings = this._createStatCard(statsRow, 'Findings', '0', 'stat-findings');
    this._els.intercepted = this._createStatCard(statsRow, 'Intercepted', '0', 'stat-intercepted');
    container.appendChild(statsRow);

    // ── Main grid: 2x2 layout ───────────────────────────────────────────────
    const grid = PE.el('div', { class: 'dash-grid' });

    // Top-left: Severity donut
    const donutCard = PE.el('div', { class: 'dash-card' });
    donutCard.appendChild(PE.el('div', { class: 'dash-card-title', text: 'Findings by Severity' }));
    this._els.donutContainer = PE.el('div', { class: 'dash-donut-container' });
    this._els.donutChart = PE.el('div', { class: 'dash-donut-chart' });
    this._els.donutLegend = PE.el('div', { class: 'dash-donut-legend' });
    this._els.donutContainer.appendChild(this._els.donutChart);
    this._els.donutContainer.appendChild(this._els.donutLegend);
    donutCard.appendChild(this._els.donutContainer);
    grid.appendChild(donutCard);

    // Top-right: Flow rate sparkline
    const sparkCard = PE.el('div', { class: 'dash-card' });
    sparkCard.appendChild(PE.el('div', { class: 'dash-card-title', text: 'Flow Rate' }));
    this._els.sparkline = PE.el('div', { class: 'dash-sparkline' });
    this._els.flowRate = PE.el('div', { class: 'dash-flow-rate' });
    sparkCard.appendChild(this._els.flowRate);
    sparkCard.appendChild(this._els.sparkline);
    grid.appendChild(sparkCard);

    // Bottom-left: Top 10 hosts bar chart
    const hostsCard = PE.el('div', { class: 'dash-card' });
    hostsCard.appendChild(PE.el('div', { class: 'dash-card-title', text: 'Top Hosts' }));
    this._els.hostsChart = PE.el('div', { class: 'dash-hosts-chart' });
    hostsCard.appendChild(this._els.hostsChart);
    grid.appendChild(hostsCard);

    // Bottom-right: Recent activity + scan progress
    const activityCard = PE.el('div', { class: 'dash-card' });
    activityCard.appendChild(PE.el('div', { class: 'dash-card-title', text: 'Recent Activity' }));
    this._els.scanProgress = PE.el('div', { class: 'dash-scan-progress' });
    this._els.activityList = PE.el('div', { class: 'dash-activity-list' });
    activityCard.appendChild(this._els.scanProgress);
    activityCard.appendChild(this._els.activityList);
    grid.appendChild(activityCard);

    container.appendChild(grid);

    // ── Event listeners ─────────────────────────────────────────────────────
    PE.bus.on('panel:activated', (id) => {
      if (id === 'dashboard') this.refresh();
    });

    PE.bus.on('flow:new', () => this._incrementFlowCount());
    PE.bus.on('finding:new', () => this._debouncedRefresh());
    PE.bus.on('scan:progress', (data) => this._updateScanProgress(data));

    // Initial load + periodic refresh
    this.refresh();
    this._interval = setInterval(() => {
      if (PE.state.activePanel === 'dashboard') this.refresh();
    }, 10000);
  },

  _createStatCard(parent, label, value, className) {
    const card = PE.el('div', { class: `dash-stat-card ${className}` });
    const valueEl = PE.el('div', { class: 'dash-stat-value', text: value });
    card.appendChild(valueEl);
    card.appendChild(PE.el('div', { class: 'dash-stat-label', text: label }));
    parent.appendChild(card);
    return valueEl;
  },

  _debouncedRefresh: PE.utils.debounce(function() {
    PE.panels.dashboard.refresh();
  }, 2000),

  _incrementFlowCount() {
    const current = parseInt(this._els.totalFlows.textContent) || 0;
    this._els.totalFlows.textContent = String(current + 1);
  },

  async refresh() {
    try {
      const data = await PE.api.get('/api/dashboard');
      this._renderStats(data);
      this._renderDonut(data.severity_counts || {});
      this._renderSparkline(data.flow_rate || []);
      this._renderTopHosts(data.top_hosts || []);
      this._renderActivity(data.recent_activity || []);
      this._renderScans(data.active_scans || []);
    } catch (e) {
      console.error('[dashboard] refresh failed:', e);
    }
  },

  _renderStats(data) {
    this._els.totalFlows.textContent = this._formatNumber(data.total_flows || 0);
    this._els.activeScans.textContent = String(data.active_scan_count || 0);

    const sev = data.severity_counts || {};
    const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0) + (sev.info || 0);
    this._els.totalFindings.textContent = String(total);

    this._els.intercepted.textContent = String(data.intercepted_count || 0);
  },

  _renderDonut(severityCounts) {
    const colorMap = {
      critical: 'var(--sev-critical, #e63946)',
      high: 'var(--sev-high, #f77f00)',
      medium: 'var(--sev-medium, #fcbf49)',
      low: 'var(--sev-low, #2a9d8f)',
      info: 'var(--sev-info, #457b9d)',
    };

    const data = [];
    const legendHtml = [];
    for (const [sev, color] of Object.entries(colorMap)) {
      const count = severityCounts[sev] || 0;
      if (count > 0) {
        data.push({ value: count, color });
      }
      legendHtml.push(
        `<div class="dash-legend-item">` +
        `<span class="dash-legend-dot" style="background:${color}"></span>` +
        `<span class="dash-legend-label">${sev.charAt(0).toUpperCase() + sev.slice(1)}</span>` +
        `<span class="dash-legend-count">${count}</span>` +
        `</div>`
      );
    }

    if (data.length) {
      PE.chart.donut(this._els.donutChart, data, { size: 140, thickness: 24, label: 'findings' });
    } else {
      this._els.donutChart.innerHTML = '<div class="empty-state"><div class="title">No findings yet</div></div>';
    }
    this._els.donutLegend.innerHTML = legendHtml.join('');
  },

  _renderSparkline(flowRate) {
    if (!flowRate.length) {
      this._els.sparkline.innerHTML = '<div class="empty-state"><div class="title">No flow data</div></div>';
      this._els.flowRate.textContent = '';
      return;
    }
    const latest = flowRate[flowRate.length - 1] || 0;
    this._els.flowRate.textContent = `${latest} req/s`;
    PE.chart.sparkline(this._els.sparkline, flowRate, {
      width: 360,
      height: 60,
      color: 'var(--accent, #6c9bff)',
    });
  },

  _renderTopHosts(hosts) {
    if (!hosts.length) {
      this._els.hostsChart.innerHTML = '<div class="empty-state"><div class="title">No hosts recorded</div></div>';
      return;
    }
    const top10 = hosts.slice(0, 10);
    const barData = top10.map(h => ({
      label: this._truncateHost(h.host || h.name || ''),
      value: h.count || h.flow_count || 0,
      color: 'var(--accent, #6c9bff)',
    }));
    PE.chart.bar(this._els.hostsChart, barData, { width: 420, height: 160, barWidth: 28 });
  },

  _renderActivity(activities) {
    if (!activities.length) {
      this._els.activityList.innerHTML = '<div class="empty-state"><div class="title">No recent activity</div></div>';
      return;
    }
    const items = activities.slice(0, 8).map(a => {
      const time = PE.utils.relativeTime(a.timestamp);
      const sevClass = a.severity ? `sev-${a.severity.toLowerCase()}` : '';
      return `<div class="dash-activity-item">` +
        `<span class="dash-activity-time">${PE.utils.escapeHtml(time)}</span>` +
        (a.severity ? `<span class="badge ${sevClass}">${PE.utils.escapeHtml(a.severity)}</span>` : '') +
        `<span class="dash-activity-text">${PE.utils.escapeHtml(a.message || a.description || '')}</span>` +
        `</div>`;
    });
    this._els.activityList.innerHTML = items.join('');
  },

  _renderScans(scans) {
    if (!scans.length) {
      this._els.scanProgress.innerHTML = '';
      return;
    }
    const html = scans.map(s => {
      const pct = s.total > 0 ? Math.round((s.completed / s.total) * 100) : 0;
      return `<div class="dash-scan-item">` +
        `<div class="dash-scan-header">` +
        `<span class="dash-scan-name">${PE.utils.escapeHtml(s.name || s.profile || 'Scan')}</span>` +
        `<span class="dash-scan-pct">${pct}%</span>` +
        `</div>` +
        `<div class="progress-bar"><div class="progress-bar-fill" style="width:${pct}%"></div></div>` +
        `</div>`;
    });
    this._els.scanProgress.innerHTML = html.join('');
  },

  _updateScanProgress(data) {
    if (PE.state.activePanel !== 'dashboard') return;
    const existing = this._els.scanProgress.querySelector(`[data-scan-id="${data.id}"]`);
    if (existing) {
      const pct = data.total > 0 ? Math.round((data.completed / data.total) * 100) : 0;
      const fill = existing.querySelector('.progress-bar-fill');
      const pctEl = existing.querySelector('.dash-scan-pct');
      if (fill) fill.style.width = pct + '%';
      if (pctEl) pctEl.textContent = pct + '%';
    } else {
      this._debouncedRefresh();
    }
  },

  _formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
  },

  _truncateHost(host) {
    if (host.length <= 12) return host;
    return host.slice(0, 10) + '..';
  },
};
