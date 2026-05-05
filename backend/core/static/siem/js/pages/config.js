import { api } from '../api.js';

export const Config = {
    async render() {
        return `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100">
                    <h3 class="text-sm font-bold text-gray-500 uppercase mb-6 flex items-center gap-2">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        SIEM Decision Thresholds
                    </h3>
                    <form id="config-form" class="space-y-6">
                        <div>
                            <div class="flex justify-between mb-2"><label class="text-xs font-bold text-gray-400 uppercase">Deceive Threshold</label><span id="val-deceive" class="font-mono text-xs font-bold">45</span></div>
                            <input type="range" name="SIEM_DECEIVE_THRESHOLD" min="0" max="200" value="45" class="w-full h-2 bg-gray-100 rounded-lg appearance-none cursor-pointer accent-primary">
                            <p class="text-[10px] text-gray-400 mt-1">Score required to route session to honeypot traps.</p>
                        </div>
                        <div>
                            <div class="flex justify-between mb-2"><label class="text-xs font-bold text-gray-400 uppercase">Block Threshold</label><span id="val-block" class="font-mono text-xs font-bold">120</span></div>
                            <input type="range" name="SIEM_BLOCK_THRESHOLD" min="0" max="500" value="120" class="w-full h-2 bg-gray-100 rounded-lg appearance-none cursor-pointer accent-blocked">
                            <p class="text-[10px] text-gray-400 mt-1">Score required to completely restrict IP access.</p>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Burst Limit (req/m)</label>
                                <input type="number" name="SIEM_BURST_LIMIT" value="20" class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                            </div>
                            <div>
                                <label class="block text-xs font-bold text-gray-400 uppercase mb-2">Brute Limit (fail/10m)</label>
                                <input type="number" name="SIEM_BRUTE_LIMIT" value="8" class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-primary">
                            </div>
                        </div>
                        <div class="pt-4">
                            <button type="submit" class="w-full py-3 bg-primary text-white rounded-lg font-bold text-sm shadow-md hover:bg-primary-dark transition-colors">SAVE CONFIGURATION</button>
                        </div>
                    </form>
                </div>

                <div class="space-y-8">
                    <div class="bg-white p-8 rounded-xl shadow-sm border border-gray-100">
                        <h3 class="text-sm font-bold text-gray-500 uppercase mb-6 flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04M12 2.944a11.955 11.955 0 01-8.618 3.04M12 2.944V12.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                            Infrastructure Health
                        </h3>
                        <div class="space-y-4">
                            <div class="flex justify-between items-center"><span class="text-sm">Database Cluster</span><span class="px-2 py-1 bg-green-50 text-green-600 text-[10px] font-bold rounded uppercase">Operational</span></div>
                            <div class="flex justify-between items-center"><span class="text-sm">Redis Score Store</span><span class="px-2 py-1 bg-green-50 text-green-600 text-[10px] font-bold rounded uppercase">Active</span></div>
                            <div class="flex justify-between items-center"><span class="text-sm">Celery Workers (4)</span><span class="px-2 py-1 bg-green-50 text-green-600 text-[10px] font-bold rounded uppercase">Running</span></div>
                            <div class="flex justify-between items-center"><span class="text-sm">GeoIP Engine</span><span class="px-2 py-1 bg-gray-50 text-gray-400 text-[10px] font-bold rounded uppercase">Loaded</span></div>
                        </div>
                    </div>
                    <div class="bg-gray-900 p-8 rounded-xl shadow-2xl text-white">
                        <h3 class="text-xs font-bold text-gray-400 uppercase mb-4">Emergency Controls</h3>
                        <p class="text-xs text-gray-400 mb-6">Immediate actions to restrict all traffic or purge caches.</p>
                        <div class="grid grid-cols-1 gap-3">
                            <button class="w-full py-2 bg-blocked text-white rounded-lg text-xs font-bold border border-red-800">ACTIVATE LOCKDOWN MODE</button>
                            <button class="w-full py-2 bg-gray-800 text-gray-300 rounded-lg text-xs font-bold border border-gray-700">FLUSH ALL SCORE CACHES</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    async init() {
        this.fetchData();
        
        const form = document.getElementById('config-form');
        form.onsubmit = (e) => this.handleSave(e);

        // Dynamic value updates for ranges
        form.querySelector('input[name="SIEM_DECEIVE_THRESHOLD"]').oninput = (e) => {
            document.getElementById('val-deceive').innerText = e.target.value;
        };
        form.querySelector('input[name="SIEM_BLOCK_THRESHOLD"]').oninput = (e) => {
            document.getElementById('val-block').innerText = e.target.value;
        };
    },

    async fetchData() {
        try {
            const data = await api.get('config/');
            const form = document.getElementById('config-form');
            for (const key in data) {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) {
                    input.value = data[key];
                    if (key === 'SIEM_DECEIVE_THRESHOLD') document.getElementById('val-deceive').innerText = data[key];
                    if (key === 'SIEM_BLOCK_THRESHOLD') document.getElementById('val-block').innerText = data[key];
                }
            }
        } catch (e) {
            console.error(e);
        }
    },

    async handleSave(e) {
        e.preventDefault();
        const fd = new FormData(e.target);
        const body = Object.fromEntries(fd.entries());
        
        try {
            await api.put('config/', body);
            alert('Configuration updated successfully. Threshold changes are live.');
        } catch (err) {
            alert(err.message);
        }
    }
};
