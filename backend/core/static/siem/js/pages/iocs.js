import { api } from '../api.js';

export const IOCs = {
    async render() {
        return `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <div class="text-xs font-bold text-gray-400 uppercase mb-2">Total Unique IOCs</div>
                    <div class="text-3xl font-bold text-primary font-mono" id="total-iocs">0</div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <div class="text-xs font-bold text-gray-400 uppercase mb-2">Unique IPs</div>
                    <div class="text-3xl font-bold text-gray-800 font-mono" id="unique-ips">0</div>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                    <div class="text-xs font-bold text-gray-400 uppercase mb-2">Recent (24h)</div>
                    <div class="text-3xl font-bold text-warning font-mono" id="recent-iocs">0</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                    <h3 class="text-sm font-bold text-gray-500 uppercase">Indicators of Compromise</h3>
                    <div class="flex gap-2">
                        <input type="text" id="ioc-search" placeholder="Filter IOCs..." class="px-4 py-2 border rounded-lg text-sm w-64">
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase bg-white">
                            <tr>
                                <th class="py-4 px-6">IOC Value</th>
                                <th class="py-4 px-6">Type</th>
                                <th class="py-4 px-6">Hits</th>
                                <th class="py-4 px-6">First Seen</th>
                                <th class="py-4 px-6">Last Seen</th>
                            </tr>
                        </thead>
                        <tbody id="iocs-table-body">
                            <tr><td colspan="5" class="py-20 text-center text-gray-400">Loading intelligence feed...</td></tr>
                        </tbody>
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
            const data = await api.get('siem/iocs/?hours=48');
            this.renderTable(data.iocs);
            document.getElementById('total-iocs').innerText = data.total;
            document.getElementById('unique-ips').innerText = data.iocs.filter(i => i.type === 'ip').length;
            document.getElementById('recent-iocs').innerText = data.iocs.length; // Simplified
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(iocs) {
        const tbody = document.getElementById('iocs-table-body');
        if (!iocs.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-20 text-center text-gray-400 font-mono">No IOCs extracted yet.</td></tr>';
            return;
        }

        tbody.innerHTML = iocs.map(i => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6 font-mono text-sm font-bold text-primary">${i.value}</td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase bg-gray-100 text-gray-600">${i.type}</span>
                </td>
                <td class="py-4 px-6 font-mono text-sm">${i.count}</td>
                <td class="py-4 px-6 text-xs text-gray-500">${new Date(i.first_seen).toLocaleString()}</td>
                <td class="py-4 px-6 text-xs text-gray-500">${new Date(i.last_seen).toLocaleString()}</td>
            </tr>
        `).join('');
    }
};
