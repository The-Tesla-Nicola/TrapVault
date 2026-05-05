import { auth } from './auth.js';
import { api } from './api.js';
import { Dashboard } from './pages/dashboard.js';
import { Sessions } from './pages/sessions.js';
import { Rules } from './pages/rules.js';
import { Users } from './pages/users.js';
import { Config } from './pages/config.js';
import { Audit } from './pages/audit.js';
import { Credentials } from './pages/credentials.js';
import { IOCs } from './pages/iocs.js';
import { Funnel } from './pages/funnel.js';
import { Analytics } from './pages/analytics.js';
import { Geo } from './pages/geo.js';
import { Alerts } from './pages/alerts.js';

const routes = {
    dashboard: Dashboard,
    analytics: Analytics,
    geo: Geo,
    sessions: Sessions,
    credentials: Credentials,
    iocs: IOCs,
    funnel: Funnel,
    alerts: Alerts,
    rules: Rules,
    users: Users,
    audit: Audit,
    config: Config
};

class App {
    constructor() {
        this.currentPage = null;
        this.init();
    }

    async init() {
        // Auth check
        if (!auth.isAuthenticated()) {
            this.showLogin();
        } else {
            this.setupUI();
            this.handleRouting();
        }

        // Global events
        window.addEventListener('popstate', () => this.handleRouting());
        document.getElementById('logout-btn')?.addEventListener('click', () => api.logout());
        document.getElementById('refresh-btn')?.addEventListener('click', () => this.refreshCurrentPage());
        
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.onsubmit = (e) => this.handleLogin(e);
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        const username = e.target.username.value;
        const password = e.target.password.value;
        const errorEl = document.getElementById('login-error');
        
        try {
            const data = await api.post('auth/login/', { username, password });
            localStorage.setItem('monitor_access_token', data.access_token);
            localStorage.setItem('monitor_refresh_token', data.refresh_token);
            localStorage.setItem('monitor_user_role', data.role);
            localStorage.setItem('monitor_username', username);
            
            window.location.reload();
        } catch (err) {
            errorEl.innerText = err.message;
            errorEl.classList.remove('hidden');
        }
    }

    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('auth-check').classList.add('hidden');
    }

    setupUI() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('auth-check').classList.remove('hidden');
        
        // Set user info
        document.getElementById('user-name').innerText = auth.getUsername();
        document.getElementById('user-role').innerText = auth.getUserRole();
        document.getElementById('user-avatar').innerText = auth.getUsername().charAt(0).toUpperCase();

        // Render Nav
        const navMenu = document.getElementById('nav-menu');
        const items = auth.getNavItems();
        
        navMenu.innerHTML = items.map(item => `
            <a href="#${item.id}" class="nav-link" data-page="${item.id}">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="${item.icon}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                ${item.label}
            </a>
        `).join('');

        // Nav click events
        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.onclick = (e) => {
                e.preventDefault();
                const page = e.currentTarget.getAttribute('data-page');
                window.location.hash = page;
            };
        });
    }

    async handleRouting() {
        const hash = window.location.hash.replace('#', '') || 'dashboard';
        
        if (!auth.hasPermission(hash)) {
            window.location.hash = 'dashboard';
            return;
        }

        // Update active link
        document.querySelectorAll('.nav-link').forEach(link => {
            if (link.getAttribute('data-page') === hash) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        const page = routes[hash];
        if (page) {
            this.currentPage = page;
            const contentArea = document.getElementById('content-area');
            const pageTitle = document.getElementById('page-title');
            
            pageTitle.innerText = hash.charAt(0).toUpperCase() + hash.slice(1).replace('-', ' ');
            contentArea.innerHTML = await page.render();
            if (page.init) page.init();
        }
    }

    refreshCurrentPage() {
        if (this.currentPage && this.currentPage.fetchData) {
            this.currentPage.fetchData();
        } else {
            this.handleRouting();
        }
    }
}

// Global App instance
window.app = new App();
