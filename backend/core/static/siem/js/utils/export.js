/**
 * Export utilities for the SIEM Dashboard
 */
import { api } from '../api.js';

export const exporter = {
    async toCSV(type) {
        try {
            const data = await api.post('export/', { type, format: 'csv' });
            if (data.download_url) {
                window.open(data.download_url, '_blank');
            }
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    },

    async toJSON(type) {
        try {
            const data = await api.post('export/', { type, format: 'json' });
            if (data.download_url) {
                window.open(data.download_url, '_blank');
            }
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    }
};
