import { api } from '../api.js';

export const Alerts = {
    async render() {
        return `
            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                    <div class="flex gap-4">
                        <select id="severity-filter" class="px-3 py-2 border rounded-lg text-sm bg-white">
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                        </select>
                        <button id="bulk-ack-btn" class="px-4 py-2 bg-primary text-white rounded-lg text-sm font-bold opacity-50 cursor-not-allowed" disabled>BULK ACKNOWLEDGE</button>
                    </div>
                    <div class="flex gap-2">
                        <input type="text" id="alert-search" placeholder="Search IP..." class="px-4 py-2 border rounded-lg text-sm w-64">
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase bg-white">
                            <tr>
                                <th class="py-4 px-6"><input type="checkbox" id="select-all-alerts"></th>
                                <th class="py-4 px-6">Timestamp</th>
                                <th class="py-4 px-6">Severity</th>
                                <th class="py-4 px-6">Attack Type</th>
                                <th class="py-4 px-6">Source IP</th>
                                <th class="py-4 px-6 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="alerts-table-body">
                            <tr><td colspan="6" class="py-20 text-center text-gray-400">Loading unacknowledged alerts...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    },

    async init() {
        this.page = 1;
        this.selectedAlerts = new Set();
        this.fetchData();

        document.getElementById('severity-filter').onchange = () => this.fetchData();
        document.getElementById('select-all-alerts').onclick = (e) => this.toggleSelectAll(e.target.checked);
        document.getElementById('bulk-ack-btn').onclick = () => this.handleBulkAck();
    },

    async fetchData() {
        try {
            const severity = document.getElementById('severity-filter').value;
            let query = `siem/alerts/?unacked=true`;
            if (severity) query += `&severity=${severity}`;
            
            const data = await api.get(query);
            this.renderTable(data.alerts);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(alerts) {
        const tbody = document.getElementById('alerts-table-body');
        if (!alerts.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-20 text-center text-gray-400 font-mono">Queue clear. No pending alerts.</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6"><input type="checkbox" class="alert-checkbox" data-id="${a.id}"></td>
                <td class="py-4 px-6 text-xs text-gray-500 font-mono">${new Date(a.timestamp).toLocaleString()}</td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase 
                        ${a.severity === 'critical' ? 'bg-red-50 text-red-600' : 
                          a.severity === 'high' ? 'bg-orange-50 text-orange-600' : 
                          'bg-blue-50 text-blue-600'}">
                        ${a.severity}
                    </span>
                </td>
                <td class="py-4 px-6 font-bold text-gray-700">${a.attack_type}</td>
                <td class="py-4 px-6 font-mono text-sm">${a.ip}</td>
                <td class="py-4 px-6 text-right">
                    <button class="ack-btn text-primary hover:text-primary-dark font-bold text-xs" data-id="${a.id}">ACKNOWLEDGE</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.ack-btn').forEach(btn => {
            btn.onclick = async () => {
                await api.post(`siem/alerts/${btn.getAttribute('data-id')}/ack/`, { note: 'Analyst acknowledged via queue.' });
                this.fetchData();
            };
        });

        tbody.querySelectorAll('.alert-checkbox').forEach(cb => {
            cb.onchange = (e) => {
                const id = e.target.getAttribute('data-id');
                if (e.target.checked) this.selectedAlerts.add(id);
                else this.selectedAlerts.delete(id);
                this.updateBulkButton();
            };
        });
    },

    toggleSelectAll(checked) {
        document.querySelectorAll('.alert-checkbox').forEach(cb => {
            cb.checked = checked;
            const id = cb.getAttribute('data-id');
            if (checked) this.selectedAlerts.add(id);
            else this.selectedAlerts.delete(id);
        });
        this.updateBulkButton();
    },

    updateBulkButton() {
        const btn = document.getElementById('bulk-ack-btn');
        if (this.selectedAlerts.size > 0) {
            btn.disabled = false;
            btn.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            btn.disabled = true;
            btn.classList.add('opacity-50', 'cursor-not-allowed');
        }
    },

    async handleBulkAck() {
        if (confirm(`Acknowledge ${this.selectedAlerts.size} alerts?`)) {
            await api.post('siem/alerts/bulk-ack/', { ids: Array.from(this.selectedAlerts) });
            this.selectedAlerts.clear();
            this.fetchData();
        }
    }
};
