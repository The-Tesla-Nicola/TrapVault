import { api } from '../api.js';

export const Audit = {
    async render() {
        return `
            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 bg-gray-50 flex justify-between items-center">
                    <h3 class="text-sm font-bold text-gray-500 uppercase">Operator Audit Trail</h3>
                    <button id="export-audit" class="px-4 py-2 border rounded-lg text-sm font-bold hover:bg-white">EXPORT LOGS</button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b uppercase bg-white">
                            <tr>
                                <th class="py-4 px-6">Timestamp</th>
                                <th class="py-4 px-6">Operator</th>
                                <th class="py-4 px-6">Action</th>
                                <th class="py-4 px-6">Details</th>
                            </tr>
                        </thead>
                        <tbody id="audit-table-body">
                            <tr><td colspan="4" class="py-20 text-center text-gray-400">Loading audit history...</td></tr>
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
            const data = await api.get('audit-log/');
            this.renderTable(data.logs || []);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(logs) {
        const tbody = document.getElementById('audit-table-body');
        if (!logs.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="py-20 text-center text-gray-400 font-mono text-sm italic">No operator actions recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => `
            <tr class="border-b border-gray-50 text-sm">
                <td class="py-4 px-6 font-mono text-xs text-gray-500">${new Date(l.timestamp).toLocaleString()}</td>
                <td class="py-4 px-6 font-bold text-primary">${l.operator}</td>
                <td class="py-4 px-6"><span class="px-2 py-1 bg-gray-100 rounded text-[10px] font-bold uppercase">${l.action}</span></td>
                <td class="py-4 px-6 text-gray-600 font-mono text-xs">${JSON.stringify(l.details)}</td>
            </tr>
        `).join('');
    }
};
