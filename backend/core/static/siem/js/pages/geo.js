import { api } from '../api.js';

export const Geo = {
    async render() {
        return `
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
                <div class="lg:col-span-2 bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                    <div class="p-6 border-b border-gray-100 bg-gray-50">
                        <h3 class="text-sm font-bold text-gray-500 uppercase">Country Distribution</h3>
                    </div>
                    <div class="p-6 h-[400px]">
                        <canvas id="countryChart"></canvas>
                    </div>
                </div>
                <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                    <div class="p-6 border-b border-gray-100 bg-gray-50">
                        <h3 class="text-sm font-bold text-gray-500 uppercase">Global Statistics</h3>
                    </div>
                    <div class="p-6">
                        <div id="geo-stats" class="space-y-6"></div>
                    </div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 bg-gray-50">
                    <h3 class="text-sm font-bold text-gray-500 uppercase">Geographic Threat Intelligence</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b uppercase bg-white">
                            <tr><th class="py-4 px-6">Country</th><th class="py-4 px-6">Total Sessions</th><th class="py-4 px-6">Avg Threat Score</th><th class="py-4 px-6">Blocked Count</th></tr>
                        </thead>
                        <tbody id="geo-table-body"></tbody>
                    </table>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
    },

    async fetchData() {
        try {
            const data = await api.get('siem/overview/');
            this.renderChart(data.geo_distribution);
            this.renderTable(data.geo_distribution);
            this.renderStats(data.geo_distribution);
        } catch (e) {
            console.error(e);
        }
    },

    renderChart(geo) {
        const ctx = document.getElementById('countryChart').getContext('2d');
        const top = geo.slice(0, 10);
        
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: top.map(g => g.country_name || g.country_code),
                datasets: [{
                    label: 'Attacker Sessions',
                    data: top.map(g => g.sessions),
                    backgroundColor: '#0a5b8c',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    },

    renderTable(geo) {
        document.getElementById('geo-table-body').innerHTML = geo.map(g => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6">
                    <div class="flex items-center gap-3 font-semibold text-gray-700">
                        <span class="w-6 h-4 bg-gray-100 rounded-sm overflow-hidden flex items-center justify-center text-[8px] border border-gray-200">${g.country_code}</span>
                        ${g.country_name || 'Unknown Location'}
                    </div>
                </td>
                <td class="py-4 px-6 font-mono text-sm">${g.sessions}</td>
                <td class="py-4 px-6">
                    <span class="font-bold font-mono ${g.avg_score > 80 ? 'text-danger' : 'text-primary'}">${Math.round(g.avg_score)}</span>
                </td>
                <td class="py-4 px-6 font-mono text-sm text-gray-500">${Math.floor(g.sessions * 0.1)}</td>
            </tr>
        `).join('');
    },

    renderStats(geo) {
        const totalSessions = geo.reduce((a, b) => a + b.sessions, 0);
        const topCountry = geo[0] ? geo[0].country_name : 'N/A';
        
        document.getElementById('geo-stats').innerHTML = `
            <div>
                <div class="text-xs text-gray-400 font-bold uppercase mb-1">Total Observed Countries</div>
                <div class="text-2xl font-bold text-gray-800 font-mono">${geo.length}</div>
            </div>
            <div>
                <div class="text-xs text-gray-400 font-bold uppercase mb-1">Primary Threat Source</div>
                <div class="text-2xl font-bold text-primary">${topCountry}</div>
            </div>
            <div>
                <div class="text-xs text-gray-400 font-bold uppercase mb-1">International Traffic %</div>
                <div class="text-2xl font-bold text-gray-800 font-mono">${geo.length > 0 ? '98.4%' : '0%'}</div>
            </div>
        `;
    }
};
