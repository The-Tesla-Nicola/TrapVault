import { api } from '../api.js';

export const Funnel = {
    charts: {},

    async render() {
        return `
            <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100 mb-8">
                <h3 class="text-sm font-bold text-gray-500 uppercase mb-8 text-center">Login Decision Pipeline (24h)</h3>
                <div class="max-w-3xl mx-auto h-[400px]">
                    <canvas id="pipelineChart"></canvas>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Top Attacker Usernames</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm">
                            <thead class="text-xs text-gray-400 border-b uppercase">
                                <tr><th class="pb-3">Username</th><th class="pb-3 text-right">Attempts</th></tr>
                            </thead>
                            <tbody id="top-usernames-body"></tbody>
                        </table>
                    </div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-4">Top Attacker IPs</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm">
                            <thead class="text-xs text-gray-400 border-b uppercase">
                                <tr><th class="pb-3">IP Address</th><th class="pb-3 text-right">Attempts</th></tr>
                            </thead>
                            <tbody id="top-ips-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
    },

    async fetchData() {
        try {
            const data = await api.get('siem/funnel/?hours=24');
            this.updateCharts(data);
            this.updateTables(data);
        } catch (e) {
            console.error(e);
        }
    },

    updateCharts(data) {
        const ctx = document.getElementById('pipelineChart').getContext('2d');
        const b = data.by_outcome;
        
        if (this.charts.funnel) this.charts.funnel.destroy();
        
        this.charts.funnel = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Total Attempts', 'Honeypot Routed', 'Real App Routed', 'Blocked'],
                datasets: [{
                    label: 'Attempts',
                    data: [
                        Object.values(b).reduce((a, v) => a + v, 0),
                        b.routed_honeypot || 0,
                        (b.real_success || 0) + (b.real_failure || 0),
                        b.blocked || 0
                    ],
                    backgroundColor: ['#6b7280', '#8b5cf6', '#10b981', '#ef4444'],
                    borderRadius: 8
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } }
            }
        });
    },

    updateTables(data) {
        document.getElementById('top-usernames-body').innerHTML = data.top_usernames.map(u => `
            <tr class="border-b border-gray-50"><td class="py-3 font-bold text-primary">${u.username}</td><td class="py-3 text-right font-mono">${u.count}</td></tr>
        `).join('');
        
        document.getElementById('top-ips-body').innerHTML = data.top_attacker_ips.map(i => `
            <tr class="border-b border-gray-50"><td class="py-3 font-mono">${i.ip_address}</td><td class="py-3 text-right font-mono">${i.count}</td></tr>
        `).join('');
    }
};
