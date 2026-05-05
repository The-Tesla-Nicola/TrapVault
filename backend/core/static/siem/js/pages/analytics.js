import { api } from '../api.js';

export const Analytics = {
    charts: {},

    async render() {
        return `
            <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100 mb-8">
                <h3 class="text-sm font-bold text-gray-500 uppercase mb-8 text-center">Threat Heatmap (30 Days)</h3>
                <div class="h-[300px]" id="heatmap-container">
                    <canvas id="heatmapChart"></canvas>
                </div>
                <div class="mt-4 flex justify-center gap-8 text-[10px] font-bold text-gray-400 uppercase">
                    <div class="flex items-center gap-2"><span class="w-3 h-3 bg-blue-50 rounded"></span> Low Activity</div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 bg-blue-400 rounded"></span> Medium</div>
                    <div class="flex items-center gap-2"><span class="w-3 h-3 bg-primary rounded"></span> High Activity</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 bg-gray-50">
                    <h3 class="text-sm font-bold text-gray-500 uppercase">Attack Type Intelligence</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b uppercase">
                            <tr><th class="py-4 px-6">Attack Vector</th><th class="py-4 px-6">Total Hits</th><th class="py-4 px-6">Avg Confidence</th><th class="py-4 px-6">Unique Sources</th></tr>
                        </thead>
                        <tbody id="analytics-table-body"></tbody>
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
            const heatmapData = await api.get('siem/heatmap/?days=30');
            const overview = await api.get('siem/overview/');
            this.renderHeatmap(heatmapData);
            this.renderTable(overview.attack_breakdown);
        } catch (e) {
            console.error(e);
        }
    },

    renderHeatmap(data) {
        const ctx = document.getElementById('heatmapChart').getContext('2d');
        if (this.charts.heatmap) this.charts.heatmap.destroy();

        // Flatten matrix for Chart.js
        const chartData = [];
        data.matrix.forEach((row, dayIndex) => {
            row.forEach((value, hourIndex) => {
                chartData.push({ x: hourIndex, y: dayIndex, v: value });
            });
        });

        this.charts.heatmap = new Chart(ctx, {
            type: 'bubble',
            data: {
                datasets: [{
                    data: chartData.map(d => ({ x: d.x, y: d.y, r: Math.min(d.v * 2, 15) })),
                    backgroundColor: (ctx) => {
                        const val = chartData[ctx.dataIndex].v;
                        if (val > 20) return '#0a5b8c';
                        if (val > 5) return '#3b82f6';
                        return '#e5e7eb';
                    }
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { min: 0, max: 23, title: { display: true, text: 'Hour of Day', font: { size: 10 } } },
                    y: { 
                        min: 0, max: 6,
                        ticks: { callback: (v) => data.days[v] },
                        title: { display: true, text: 'Day of Week', font: { size: 10 } }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    },

    renderTable(breakdown) {
        document.getElementById('analytics-table-body').innerHTML = breakdown.map(a => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6 font-bold text-primary">${a.attack_type}</td>
                <td class="py-4 px-6 font-mono text-sm">${a.count}</td>
                <td class="py-4 px-6">
                    <div class="flex items-center gap-2">
                        <div class="w-16 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                            <div class="h-full bg-info" style="width: ${a.avg_conf * 100}%"></div>
                        </div>
                        <span class="text-xs font-mono">${(a.avg_conf * 100).toFixed(0)}%</span>
                    </div>
                </td>
                <td class="py-4 px-6 font-mono text-sm text-gray-500">${a.unique_fps}</td>
            </tr>
        `).join('');
    }
};
