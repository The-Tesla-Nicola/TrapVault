/**
 * KPI Cards Component
 */

export const KPICards = {
    render(kpis) {
        const cards = [
            { id: 'total_alerts', label: 'Total Alerts', val: kpis.total_alerts, color: 'text-primary' },
            { id: 'alerts_1h', label: 'Alerts (1h)', val: kpis.alerts_1h, color: 'text-gray-800' },
            { id: 'alerts_24h', label: 'Alerts (24h)', val: kpis.alerts_24h, color: 'text-gray-800' },
            { id: 'critical', label: 'Critical Unacked', val: kpis.critical_unacked, color: 'text-danger', badge: true },
            { id: 'high', label: 'High Unacked', val: kpis.high_unacked, color: 'text-warning', badge: true },
            { id: 'deceived', label: 'Deceived', val: kpis.sessions_deceived, color: 'text-deceived' },
            { id: 'blocked', label: 'Blocked', val: kpis.sessions_blocked, color: 'text-blocked' },
            { id: 'real_logins', label: 'Real Logins (24h)', val: kpis.real_logins_24h, color: 'text-success' },
            { id: 'brute_force', label: 'Brute Force (24h)', val: kpis.brute_force_24h, color: 'text-orange-600' },
            { id: 'unique', label: 'Unique Attackers', val: kpis.unique_attackers_24h, color: 'text-info' },
            { id: 'confidence', label: 'Avg Confidence', val: (kpis.avg_confidence * 100).toFixed(0) + '%', color: 'text-success' },
            { id: 'top_attack', label: 'Top Attack', val: kpis.top_attack_type, color: 'text-primary' }
        ];

        return cards.map(c => `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 hover:shadow-md transition-shadow relative overflow-hidden">
                <div class="text-xs font-bold text-gray-400 uppercase mb-2">${c.label}</div>
                <div class="text-3xl font-bold ${c.color} font-mono">${c.val}</div>
                ${c.badge && c.val > 0 ? `<div class="absolute top-0 right-0 w-1 h-full ${c.id === 'critical' ? 'bg-danger' : 'bg-warning'}"></div>` : ''}
            </div>
        `).join('');
    }
};
