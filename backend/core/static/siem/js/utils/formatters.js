/**
 * Data formatters for the SIEM Dashboard
 */

export const formatters = {
    date(isoString) {
        if (!isoString) return '—';
        return new Date(isoString).toLocaleString();
    },

    time(isoString) {
        if (!isoString) return '—';
        return new Date(isoString).toLocaleTimeString();
    },

    ip(ip) {
        return `<span class="font-mono text-xs">${ip || '0.0.0.0'}</span>`;
    },

    truncate(str, len = 12) {
        if (!str) return '—';
        if (str.length <= len) return str;
        return str.substring(0, len) + '…';
    },

    currency(amount) {
        return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
    },

    score(score) {
        let color = 'text-success';
        if (score >= 100) color = 'text-danger';
        else if (score >= 50) color = 'text-warning';
        return `<span class="font-bold font-mono ${color}">${score}</span>`;
    }
};
