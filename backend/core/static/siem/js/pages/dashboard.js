import { api } from '../api.js';

export const Dashboard = {
    charts: {},

    async render() {
        return `
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" id="kpi-grid">
                <!-- Skeleton Loaders -->
                ${Array(8).fill('<div class="h-32 bg-gray-200 animate-pulse rounded-xl"></div>').join('')}
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Hourly Attack Trend</h3>
                    <div class="h-[300px]">
                        <canvas id="hourlyTrendChart"></canvas>
                    </div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Severity Distribution</h3>
                    <div class="h-[300px] flex justify-center">
                        <canvas id="severityDistChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                <div class="lg:col-span-2 bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Live Threat Feed</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left">
                            <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase">
                                <tr>
                                    <th class="pb-3">Timestamp</th>
                                    <th class="pb-3">Attack Type</th>
                                    <th class="pb-3">IP Address</th>
                                    <th class="pb-3">Routing</th>
                                </tr>
                            </thead>
                            <tbody id="live-feed-body">
                                <tr><td colspan="4" class="py-8 text-center text-gray-400">Loading live data...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Routing Funnel</h3>
                    <div class="h-[400px]">
                        <canvas id="funnelChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Top Attack Types</h3>
                    <div class="h-[300px]">
                        <canvas id="attackTypeChart"></canvas>
                    </div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">30-Day Attack Trend</h3>
                    <div class="h-[300px]">
                        <canvas id="dailyTrendChart"></canvas>
                    </div>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
        this.startPolling();
    },

    startPolling() {
        this.pollInterval = setInterval(() => this.fetchData(), 30000);
        this.feedInterval = setInterval(() => this.pollLiveFeed(), 10000);
    },

    destroy() {
        clearInterval(this.pollInterval);
        clearInterval(this.feedInterval);
    },

    async fetchData() {
        try {
            const data = await api.get('siem/overview/');
            this.updateKPIs(data.kpis);
            this.updateCharts(data);
            this.pollLiveFeed(); // Initial feed load
            document.getElementById('last-updated').innerText = `Sync: ${new Date().toLocaleTimeString()}`;
        } catch (e) {
            console.error(e);
        }
    },

    updateKPIs(kpis) {
        const grid = document.getElementById('kpi-grid');
        const cards = [
            { label: 'Total Alerts', val: kpis.total_alerts, color: 'text-primary' },
            { label: 'Alerts (Last Hour)', val: kpis.alerts_1h, color: 'text-gray-800' },
            { label: 'Alerts (24h)', val: kpis.alerts_24h, color: 'text-gray-800' },
            { label: 'Critical Unacked', val: kpis.critical_unacked, color: 'text-danger' },
            { label: 'High Unacked', val: kpis.high_unacked, color: 'text-warning' },
            { label: 'Deceived', val: kpis.sessions_deceived, color: 'text-deceived' },
            { label: 'Blocked', val: kpis.sessions_blocked, color: 'text-blocked' },
            { label: 'Real Logins (24h)', val: kpis.real_logins_24h, color: 'text-success' },
            { label: 'Brute Force (24h)', val: kpis.brute_force_24h, color: 'text-orange-600' },
            { label: 'Unique Attackers', val: kpis.unique_attackers_24h, color: 'text-info' },
            { label: 'Avg Confidence', val: (kpis.avg_confidence * 100).toFixed(0) + '%', color: 'text-success' },
            { label: 'Top Attack', val: kpis.top_attack_type, color: 'text-primary' }
        ];
        
        grid.innerHTML = cards.map(c => `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                <div class="text-xs font-bold text-gray-400 uppercase mb-2">${c.label}</div>
                <div class="text-3xl font-bold ${c.color} font-mono">${c.val}</div>
            </div>
        `).join('');
    },

    updateCharts(data) {
        // Hourly Trend
        this.renderChart('hourlyTrendChart', 'bar', {
            labels: data.hourly_trend.map(h => h.hour.split('T')[1].substring(0,5)),
            datasets: [
                {
                    label: 'Critical',
                    data: data.hourly_trend.map(h => h.critical),
                    backgroundColor: '#dc2626',
                },
                {
                    label: 'High',
                    data: data.hourly_trend.map(h => h.high),
                    backgroundColor: '#f59e0b',
                },
                {
                    label: 'Medium',
                    data: data.hourly_trend.map(h => h.medium),
                    backgroundColor: '#3b82f6',
                }
            ]
        }, { stacked: true });

        // Severity Doughnut
        this.renderChart('severityDistChart', 'doughnut', {
            labels: data.severity_dist.map(s => s.severity.toUpperCase()),
            datasets: [{
                data: data.severity_dist.map(s => s.count),
                backgroundColor: ['#dc2626', '#f59e0b', '#3b82f6', '#10b981', '#6b7280']
            }]
        });

        // Funnel
        const f = data.routing_funnel;
        this.renderChart('funnelChart', 'bar', {
            labels: ['Total', 'Real App', 'Honeypot', 'Blocked'],
            datasets: [{
                label: 'Logins',
                data: [f.total_logins, f.routed_real, f.routed_deceive, f.blocked],
                backgroundColor: ['#6b7280', '#10b981', '#8b5cf6', '#ef4444']
            }]
        }, { indexAxis: 'y' });

        // Attack Type Breakdown
        this.renderChart('attackTypeChart', 'bar', {
            labels: data.attack_breakdown.map(a => a.attack_type),
            datasets: [{
                label: 'Hits',
                data: data.attack_breakdown.map(a => a.count),
                backgroundColor: '#0a5b8c'
            }]
        }, { indexAxis: 'y' });

        // Daily Trend
        this.renderChart('dailyTrendChart', 'line', {
            labels: data.daily_trend.map(d => d.date),
            datasets: [{
                label: 'Daily Alerts',
                data: data.daily_trend.map(d => d.count),
                borderColor: '#0a5b8c',
                backgroundColor: 'rgba(10, 91, 140, 0.1)',
                fill: true,
                tension: 0.4
            }]
        });
    },

    renderChart(id, type, config, options = {}) {
        const el = document.getElementById(id);
        if (!el) return;
        if (this.charts[id]) this.charts[id].destroy();
        
        const ctx = el.getContext('2d');
        this.charts[id] = new Chart(ctx, {
            type,
            data: config,
            options: { 
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { 
                        display: type === 'doughnut' || (options.stacked),
                        position: 'bottom',
                        labels: { boxWidth: 12, padding: 15, font: { size: 11 } }
                    } 
                },
                scales: type === 'doughnut' ? {} : {
                    x: { stacked: options.stacked || false, grid: { display: false } },
                    y: { stacked: options.stacked || false, beginAtZero: true }
                }
            }
        });
    },

    async pollLiveFeed() {
        try {
            const data = await api.get('siem/live/?seconds=15');
            const tbody = document.getElementById('live-feed-body');
            if (!tbody) return;

            if (data.events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-gray-400 font-mono text-xs">Waiting for new events...</td></tr>';
                return;
            }

            tbody.innerHTML = data.events.map(ev => `
                <tr class="text-sm border-b border-gray-50 hover:bg-gray-50 transition-colors cursor-pointer" onclick="window.location.hash='sessions'">
                    <td class="py-3 font-mono text-xs text-gray-500">${ev.timestamp.split('T')[1].split('.')[0]}</td>
                    <td class="py-3 font-semibold text-gray-700">${ev.attack_type}</td>
                    <td class="py-3 font-mono text-xs">${ev.ip}</td>
                    <td class="py-3">
                        <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase 
                            ${ev.severity === 'critical' ? 'bg-red-50 text-red-600' : 
                              ev.severity === 'high' ? 'bg-orange-50 text-orange-600' : 
                              'bg-blue-50 text-blue-600'}">
                            ${ev.routing}
                        </span>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            console.error(e);
        }
    }
};
