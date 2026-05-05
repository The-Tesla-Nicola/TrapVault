import { api } from '../api.js';

export const Sessions = {
    async render() {
        return `
            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50">
                    <div class="flex gap-4">
                        <select id="threat-filter" class="px-3 py-2 border rounded-lg text-sm bg-white">
                            <option value="">All Threat Levels</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                        </select>
                        <select id="blocked-filter" class="px-3 py-2 border rounded-lg text-sm bg-white">
                            <option value="">All Status</option>
                            <option value="true">Blocked Only</option>
                            <option value="false">Active Only</option>
                        </select>
                    </div>
                    <div class="flex gap-2">
                        <input type="text" id="session-search" placeholder="Search IP or Fingerprint..." class="px-4 py-2 border rounded-lg text-sm w-64">
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase bg-white">
                            <tr>
                                <th class="py-4 px-6">IP Address</th>
                                <th class="py-4 px-6">Fingerprint</th>
                                <th class="py-4 px-6">Threat Score</th>
                                <th class="py-4 px-6">Last Seen</th>
                                <th class="py-4 px-6">Status</th>
                                <th class="py-4 px-6 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="sessions-table-body">
                            <tr><td colspan="6" class="py-20 text-center text-gray-400">Loading sessions...</td></tr>
                        </tbody>
                    </table>
                </div>
                <div id="pagination" class="p-4 border-t border-gray-100 flex justify-between items-center bg-white">
                    <span class="text-sm text-gray-500">Showing <span id="pagination-count">0</span> sessions</span>
                    <div class="flex gap-2">
                        <button id="prev-page" class="px-4 py-2 border rounded-lg text-sm hover:bg-gray-50 disabled:opacity-50">Previous</button>
                        <button id="next-page" class="px-4 py-2 border rounded-lg text-sm hover:bg-gray-50 disabled:opacity-50">Next</button>
                    </div>
                </div>
            </div>

            <!-- Modal for Session Details -->
            <div id="session-modal" class="fixed inset-0 bg-gray-900 bg-opacity-50 z-[60] flex items-center justify-center hidden">
                <div class="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
                    <div class="p-6 border-b border-gray-100 flex justify-between items-center">
                        <h2 class="text-xl font-bold">Session Intelligence</h2>
                        <button onclick="document.getElementById('session-modal').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        </button>
                    </div>
                    <div class="p-8 overflow-y-auto flex-1" id="session-details-content">
                        <!-- Details injected here -->
                    </div>
                </div>
            </div>
        `;
    },

    async init() {
        this.page = 1;
        this.fetchData();
        
        document.getElementById('prev-page').onclick = () => { if (this.page > 1) { this.page--; this.fetchData(); } };
        document.getElementById('next-page').onclick = () => { this.page++; this.fetchData(); };
        document.getElementById('threat-filter').onchange = () => { this.page = 1; this.fetchData(); };
        document.getElementById('blocked-filter').onchange = () => { this.page = 1; this.fetchData(); };
        document.getElementById('session-search').oninput = (e) => { 
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => { this.page = 1; this.fetchData(); }, 500);
        };
    },

    async fetchData() {
        try {
            const threat = document.getElementById('threat-filter').value;
            const blocked = document.getElementById('blocked-filter').value;
            const search = document.getElementById('session-search').value;
            
            let query = `sessions/?page=${this.page}`;
            if (threat) query += `&threat_level=${threat}`;
            if (blocked) query += `&is_blocked=${blocked}`;
            
            const data = await api.get(query);
            this.renderTable(data.sessions);
            this.updatePagination(data.pagination);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(sessions) {
        const tbody = document.getElementById('sessions-table-body');
        if (!sessions.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-20 text-center text-gray-400 font-mono">No sessions found matching filters.</td></tr>';
            return;
        }

        tbody.innerHTML = sessions.map(s => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6 font-mono text-sm font-semibold text-primary">${s.ip_address}</td>
                <td class="py-4 px-6 font-mono text-xs text-gray-500">${s.fingerprint.substring(0, 12)}...</td>
                <td class="py-4 px-6">
                    <div class="flex items-center gap-3">
                        <div class="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden w-24">
                            <div class="h-full bg-primary" style="width: ${Math.min(s.threat_score, 100)}%"></div>
                        </div>
                        <span class="text-xs font-bold ${this.getScoreColor(s.threat_score)}">${s.threat_score}</span>
                    </div>
                </td>
                <td class="py-4 px-6 text-sm text-gray-500">${new Date(s.last_seen).toLocaleString()}</td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase ${s.is_blocked ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'}">
                        ${s.is_blocked ? 'Blocked' : 'Active'}
                    </span>
                </td>
                <td class="py-4 px-6 text-right">
                    <button class="view-btn text-primary hover:text-primary-dark font-bold text-xs" data-id="${s.id}">VIEW INTEL</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.view-btn').forEach(btn => {
            btn.onclick = () => this.showDetails(btn.getAttribute('data-id'));
        });
    },

    getScoreColor(score) {
        if (score >= 100) return 'text-danger';
        if (score >= 50) return 'text-warning';
        return 'text-success';
    },

    updatePagination(pag) {
        document.getElementById('pagination-count').innerText = pag.total;
        document.getElementById('prev-page').disabled = this.page === 1;
        document.getElementById('next-page').disabled = this.page >= pag.total_pages;
    },

    async showDetails(id) {
        const modal = document.getElementById('session-modal');
        const content = document.getElementById('session-details-content');
        modal.classList.remove('hidden');
        content.innerHTML = '<div class="py-20 text-center animate-pulse text-gray-400">Analyzing session telemetry...</div>';

        try {
            const data = await api.get(`sessions/${id}/`);
            const s = data.session;
            
            content.innerHTML = `
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
                    <div>
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Core Telemetry</h3>
                        <div class="space-y-3">
                            <div class="flex justify-between border-b pb-2"><span class="text-gray-500 text-sm">IP Address</span><span class="font-mono font-bold">${s.ip_address}</span></div>
                            <div class="flex justify-between border-b pb-2"><span class="text-gray-500 text-sm">Geo Location</span><span class="text-sm font-semibold">${s.city}, ${s.country_name}</span></div>
                            <div class="flex justify-between border-b pb-2"><span class="text-gray-500 text-sm">First Seen</span><span class="text-sm">${new Date(s.first_seen).toLocaleString()}</span></div>
                            <div class="flex justify-between border-b pb-2"><span class="text-gray-500 text-sm">User Agent</span><span class="text-xs max-w-[200px] truncate" title="${s.user_agent}">${s.user_agent}</span></div>
                        </div>
                    </div>
                    <div class="bg-gray-50 p-6 rounded-xl">
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Risk Profile</h3>
                        <div class="text-center">
                            <div class="text-5xl font-bold font-mono ${this.getScoreColor(s.threat_score)} mb-2">${s.threat_score}</div>
                            <div class="text-xs font-bold uppercase tracking-widest text-gray-500">${s.threat_level} threat level</div>
                        </div>
                        <div class="mt-6 flex justify-center gap-4">
                            <button class="px-6 py-2 bg-blocked text-white rounded-lg font-bold text-sm" id="block-btn">
                                ${s.is_blocked ? 'UNBLOCK SOURCE' : 'BLOCK SOURCE'}
                            </button>
                        </div>
                    </div>
                </div>

                <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Event Timeline (${data.timeline.length})</h3>
                <div class="border rounded-xl overflow-hidden mb-8">
                    <table class="w-full text-left">
                        <thead class="bg-gray-50 text-xs font-bold">
                            <tr><th class="p-3">Time</th><th class="p-3">Attack</th><th class="p-3">Method</th><th class="p-3">Path</th></tr>
                        </thead>
                        <tbody class="text-xs">
                            ${data.timeline.map(t => `
                                <tr class="border-t">
                                    <td class="p-3 text-gray-500">${t.timestamp.split('T')[1].split('.')[0]}</td>
                                    <td class="p-3 font-bold">${t.attack_type}</td>
                                    <td class="p-3 font-mono">${t.method}</td>
                                    <td class="p-3 font-mono text-primary">${t.path}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Captured Credentials</h3>
                        ${data.credentials.length ? data.credentials.map(c => `
                            <div class="p-3 border rounded-lg mb-2 bg-white flex justify-between items-center">
                                <div><div class="text-sm font-bold text-primary">${c.username}</div><div class="text-xs font-mono text-gray-400">${c.password}</div></div>
                                <span class="text-[10px] font-bold uppercase px-2 py-1 bg-red-50 text-red-600 rounded">${c.strength}</span>
                            </div>
                        `).join('') : '<div class="text-sm text-gray-400 italic">No credentials captured.</div>'}
                    </div>
                    <div>
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Asset Interactions</h3>
                        ${data.deception_interactions.length ? data.deception_interactions.map(d => `
                            <div class="p-3 border rounded-lg mb-2 bg-white">
                                <div class="text-sm font-bold">${d.asset_name}</div>
                                <div class="text-xs text-gray-500">${d.interaction_type} at ${d.timestamp.split('T')[1].split('.')[0]}</div>
                            </div>
                        `).join('') : '<div class="text-sm text-gray-400 italic">No interactions recorded.</div>'}
                    </div>
                </div>
            `;

            document.getElementById('block-btn').onclick = async () => {
                const action = s.is_blocked ? 'unblock' : 'block';
                if (confirm(`Are you sure you want to ${action} this session?`)) {
                    await api.post(`sessions/${id}/action/`, { action });
                    this.showDetails(id);
                    this.fetchData();
                }
            };

        } catch (e) {
            content.innerHTML = `<div class="py-20 text-center text-danger font-bold">Failed to load intelligence data: ${e.message}</div>`;
        }
    }
};
