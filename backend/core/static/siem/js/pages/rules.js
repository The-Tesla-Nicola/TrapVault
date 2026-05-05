import { api } from '../api.js';

export const Rules = {
    async render() {
        return `
            <div class="flex justify-between items-center mb-8">
                <div>
                    <h2 class="text-xl font-bold">Automation Rules</h2>
                    <p class="text-sm text-gray-500">Configure automated actions and notifications.</p>
                </div>
                <button id="add-rule-btn" class="px-6 py-2 bg-primary text-white rounded-lg font-bold text-sm shadow-sm hover:bg-primary-dark transition-colors">CREATE NEW RULE</button>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase">
                            <tr>
                                <th class="py-4 px-6">Rule Name</th>
                                <th class="py-4 px-6">Condition</th>
                                <th class="py-4 px-6">Channels</th>
                                <th class="py-4 px-6">Auto-Block</th>
                                <th class="py-4 px-6">Status</th>
                                <th class="py-4 px-6 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="rules-table-body">
                            <tr><td colspan="6" class="py-20 text-center text-gray-400">Loading ruleset...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Rule Modal -->
            <div id="rule-modal" class="fixed inset-0 bg-gray-900 bg-opacity-50 z-[60] flex items-center justify-center hidden">
                <div class="bg-white rounded-2xl shadow-2xl w-full max-w-xl">
                    <div class="p-6 border-b border-gray-100 flex justify-between items-center">
                        <h2 class="text-xl font-bold" id="modal-title">Create Alert Rule</h2>
                        <button onclick="document.getElementById('rule-modal').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        </button>
                    </div>
                    <form id="rule-form" class="p-8 space-y-6">
                        <div>
                            <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Rule Name</label>
                            <input type="text" name="name" required class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Match Severity</label>
                                <select name="match_severity" class="w-full px-4 py-2 border rounded-lg">
                                    <option value="">Any</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Min Confidence</label>
                                <input type="number" name="min_confidence" step="0.1" min="0" max="1" value="0.7" class="w-full px-4 py-2 border rounded-lg">
                            </div>
                        </div>
                        <div class="flex items-center gap-4 py-4 border-y border-gray-50">
                            <label class="flex items-center gap-2 cursor-pointer">
                                <input type="checkbox" name="auto_block" class="w-4 h-4 text-primary rounded">
                                <span class="text-sm font-semibold">Enable Auto-Block</span>
                            </label>
                            <label class="flex items-center gap-2 cursor-pointer">
                                <input type="checkbox" name="is_active" checked class="w-4 h-4 text-primary rounded">
                                <span class="text-sm font-semibold">Rule Active</span>
                            </label>
                        </div>
                        <div class="flex justify-end gap-3 pt-4">
                            <button type="button" onclick="document.getElementById('rule-modal').classList.add('hidden')" class="px-6 py-2 border rounded-lg font-bold text-sm">CANCEL</button>
                            <button type="submit" class="px-6 py-2 bg-primary text-white rounded-lg font-bold text-sm">SAVE RULE</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
        document.getElementById('add-rule-btn').onclick = () => {
            document.getElementById('rule-form').reset();
            document.getElementById('modal-title').innerText = 'Create Alert Rule';
            document.getElementById('rule-modal').classList.remove('hidden');
            this.editingId = null;
        };

        document.getElementById('rule-form').onsubmit = (e) => this.handleSave(e);
    },

    async fetchData() {
        try {
            const data = await api.get('siem/rules/');
            this.renderTable(data.rules);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(rules) {
        const tbody = document.getElementById('rules-table-body');
        if (!rules.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-20 text-center text-gray-400 font-mono">No active rules defined.</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(r => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors">
                <td class="py-4 px-6 font-bold text-gray-800">${r.name}</td>
                <td class="py-4 px-6 text-sm text-gray-500">
                    Severity: <span class="font-bold text-gray-700">${r.match_severity || 'Any'}</span>, 
                    Conf: <span class="font-bold text-gray-700">${r.min_confidence}</span>
                </td>
                <td class="py-4 px-6">
                    <span class="text-xs font-bold uppercase text-gray-400">${r.notification_channel || 'Database'}</span>
                </td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase ${r.auto_block ? 'bg-red-50 text-red-600' : 'bg-gray-50 text-gray-400'}">
                        ${r.auto_block ? 'Enabled' : 'Disabled'}
                    </span>
                </td>
                <td class="py-4 px-6">
                    <div class="flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full ${r.is_active !== false ? 'bg-green-500' : 'bg-gray-300'}"></span>
                        <span class="text-xs font-semibold">${r.is_active !== false ? 'Active' : 'Inactive'}</span>
                    </div>
                </td>
                <td class="py-4 px-6 text-right">
                    <button class="delete-btn text-danger hover:text-red-700 font-bold text-xs" data-id="${r.id}">DELETE</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.delete-btn').forEach(btn => {
            btn.onclick = async () => {
                if (confirm('Permanently delete this rule?')) {
                    await api.delete(`siem/rules/${btn.getAttribute('data-id')}/`);
                    this.fetchData();
                }
            };
        });
    },

    async handleSave(e) {
        e.preventDefault();
        const fd = new FormData(e.target);
        const body = Object.fromEntries(fd.entries());
        body.auto_block = !!body.auto_block;
        body.is_active = !!body.is_active;
        body.min_confidence = parseFloat(body.min_confidence);

        try {
            await api.post('siem/rules/', body);
            document.getElementById('rule-modal').classList.add('hidden');
            this.fetchData();
        } catch (err) {
            alert(err.message);
        }
    }
};
