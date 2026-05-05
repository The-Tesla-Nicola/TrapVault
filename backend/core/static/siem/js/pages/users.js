import { api } from '../api.js';

export const Users = {
    async render() {
        return `
            <div class="flex justify-between items-center mb-8">
                <div>
                    <h2 class="text-xl font-bold">Legitimate Banking Customers</h2>
                    <p class="text-sm text-gray-500">Real users used for transparent proxy testing.</p>
                </div>
                <button id="add-user-btn" class="px-6 py-2 bg-primary text-white rounded-lg font-bold text-sm shadow-sm hover:bg-primary-dark transition-colors">ENROLL NEW CUSTOMER</button>
            </div>

            <div class="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead class="text-xs text-gray-400 border-b border-gray-50 uppercase">
                            <tr>
                                <th class="py-4 px-6">Customer</th>
                                <th class="py-4 px-6">Account #</th>
                                <th class="py-4 px-6">Status</th>
                                <th class="py-4 px-6">Last Login</th>
                                <th class="py-4 px-6 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="users-table-body">
                            <tr><td colspan="5" class="py-20 text-center text-gray-400">Fetching customer records...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- User Modal -->
            <div id="user-modal" class="fixed inset-0 bg-gray-900 bg-opacity-50 z-[60] flex items-center justify-center hidden">
                <div class="bg-white rounded-2xl shadow-2xl w-full max-w-xl">
                    <div class="p-6 border-b border-gray-100 flex justify-between items-center">
                        <h2 class="text-xl font-bold">Enroll Bank Customer</h2>
                        <button onclick="document.getElementById('user-modal').classList.add('hidden')" class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        </button>
                    </div>
                    <form id="user-form" class="p-8 space-y-4">
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Username</label>
                                <input type="text" name="username" required class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                            </div>
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Account Number</label>
                                <input type="text" name="account_number" required placeholder="XXXX-XXXX-XXXX" class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                            </div>
                        </div>
                        <div>
                            <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Full Name</label>
                            <input type="text" name="full_name" required class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                        </div>
                        <div>
                            <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Email Address</label>
                            <input type="email" name="email" required class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                        </div>
                        <div>
                            <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Password</label>
                            <input type="password" name="password" required minlength="10" class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                            <p class="text-[10px] text-gray-400 mt-1">Minimum 10 characters required for production security.</p>
                        </div>
                        <div class="flex justify-end gap-3 pt-6">
                            <button type="button" onclick="document.getElementById('user-modal').classList.add('hidden')" class="px-6 py-2 border rounded-lg font-bold text-sm">CANCEL</button>
                            <button type="submit" class="px-6 py-2 bg-primary text-white rounded-lg font-bold text-sm">ENROLL CUSTOMER</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
        document.getElementById('add-user-btn').onclick = () => {
            document.getElementById('user-form').reset();
            document.getElementById('user-modal').classList.remove('hidden');
        };
        document.getElementById('user-form').onsubmit = (e) => this.handleSave(e);
    },

    async fetchData() {
        try {
            const data = await api.get('siem/real-users/');
            this.renderTable(data.users);
        } catch (e) {
            console.error(e);
        }
    },

    renderTable(users) {
        const tbody = document.getElementById('users-table-body');
        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-20 text-center text-gray-400 font-mono">No customers enrolled in the real banking database.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => `
            <tr class="border-b border-gray-50 hover:bg-gray-50 transition-colors text-sm">
                <td class="py-4 px-6">
                    <div class="font-bold text-gray-800">${u.full_name}</div>
                    <div class="text-xs text-gray-400 font-mono">${u.username} | ${u.email}</div>
                </td>
                <td class="py-4 px-6 font-mono text-xs text-gray-500">${u.account_number}</td>
                <td class="py-4 px-6">
                    <span class="px-2 py-1 rounded-full text-[10px] font-bold uppercase ${u.is_active ? 'bg-green-50 text-green-600' : 'bg-red-50 text-red-600'}">
                        ${u.is_active ? 'Verified' : 'Suspended'}
                    </span>
                </td>
                <td class="py-4 px-6 text-xs text-gray-400">${u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
                <td class="py-4 px-6 text-right">
                    <button class="delete-btn text-danger hover:text-red-700 font-bold text-xs" data-id="${u.id}">REMOVE</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.delete-btn').forEach(btn => {
            btn.onclick = async () => {
                if (confirm('Permanently remove this customer from the database?')) {
                    await api.delete(`siem/real-users/${btn.getAttribute('data-id')}/`);
                    this.fetchData();
                }
            };
        });
    },

    async handleSave(e) {
        e.preventDefault();
        const fd = new FormData(e.target);
        const body = Object.fromEntries(fd.entries());

        try {
            await api.post('siem/real-users/', body);
            document.getElementById('user-modal').classList.add('hidden');
            this.fetchData();
        } catch (err) {
            alert(err.message);
        }
    }
};
