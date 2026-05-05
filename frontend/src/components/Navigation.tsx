import React from 'react';
import { User } from '../types';

interface Props { user: User; onLogout: () => void; activeTab: string; onTabChange: (tab: string) => void; }

const TABS = [
  { id: 'overview', label: 'Overview', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { id: 'accounts', label: 'Accounts', icon: 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z' },
  { id: 'transfer', label: 'Transfers', icon: 'M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4' },
  { id: 'admin', label: 'Admin Panel', icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z', badge: true },
  { id: 'settings', label: 'Settings', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
];

const Navigation: React.FC<Props> = ({ user, onLogout, activeTab, onTabChange }) => {
  const s = styles;
  return (
    <aside style={s.sidebar}>
      <div style={s.brand}>
        <div style={s.brandIcon}>
          <svg width="18" height="18" fill="none" stroke="white" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4V10z"/>
          </svg>
        </div>
        <div>
          <div style={s.brandName}>SecureBank</div>
          <div style={s.brandSub}>Online Banking</div>
        </div>
      </div>

      <div style={s.userSection}>
        <div style={s.avatar}>{(user.name || user.username).slice(0,2).toUpperCase()}</div>
        <div>
          <div style={s.userName}>{user.name || user.username}</div>
          <div style={s.userAcct}>Acct: {user.account || '****4892'}</div>
        </div>
      </div>

      <nav style={s.nav}>
        {TABS.map(tab => (
          <button
            key={tab.id}
            style={{ ...s.navItem, ...(activeTab === tab.id ? s.navItemActive : {}) }}
            onClick={() => onTabChange(tab.id)}
          >
            <svg style={s.navIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d={tab.icon}/>
            </svg>
            {tab.label}
            {tab.badge && <span style={s.badge}>!</span>}
          </button>
        ))}
      </nav>

      <div style={s.footer}>
        <div style={s.sessionStatus}>
          <div style={s.sessionDot}/>
          <span>Session active</span>
        </div>
        <button style={s.logoutBtn} onClick={onLogout}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
          </svg>
          Sign Out Securely
        </button>
      </div>
    </aside>
  );
};

const C = {
  navy: '#0a2540', blue: '#1a56db', gray50: '#f9fafb',
  white: '#ffffff', border: 'rgba(255,255,255,.08)',
};

const styles: Record<string, React.CSSProperties> = {
  sidebar: { width: 240, background: C.navy, display: 'flex', flexDirection: 'column', position: 'fixed', top: 0, left: 0, bottom: 0, zIndex: 100, fontFamily: "'Inter','IBM Plex Sans',system-ui,sans-serif" },
  brand: { padding: '20px 16px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 },
  brandIcon: { width: 34, height: 34, background: C.blue, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 },
  brandName: { color: '#fff', fontWeight: 700, fontSize: 15 },
  brandSub: { color: 'rgba(255,255,255,.4)', fontSize: 10 },
  userSection: { padding: '14px 16px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 },
  avatar: { width: 34, height: 34, borderRadius: '50%', background: C.blue, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 700, fontSize: 12, flexShrink: 0 },
  userName: { color: '#fff', fontWeight: 600, fontSize: 13 },
  userAcct: { color: 'rgba(255,255,255,.4)', fontSize: 10, marginTop: 2, fontFamily: 'monospace' },
  nav: { flex: 1, padding: '10px 0', display: 'flex', flexDirection: 'column', gap: 2 },
  navItem: { width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '9px 16px', background: 'none', border: 'none', color: 'rgba(255,255,255,.5)', fontSize: 13, fontWeight: 500, cursor: 'pointer', textAlign: 'left', transition: 'all .12s', borderLeft: '2px solid transparent', position: 'relative' },
  navItemActive: { color: '#fff', background: 'rgba(255,255,255,.07)', borderLeftColor: C.blue },
  navIcon: { width: 16, height: 16, flexShrink: 0 },
  badge: { marginLeft: 'auto', background: '#dc2626', color: '#fff', fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 10 },
  footer: { padding: '14px 16px', borderTop: `1px solid ${C.border}` },
  sessionStatus: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'rgba(255,255,255,.4)', marginBottom: 10 },
  sessionDot: { width: 7, height: 7, borderRadius: '50%', background: '#10b981' },
  logoutBtn: { width: '100%', padding: '9px 12px', background: 'rgba(255,255,255,.06)', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, color: 'rgba(255,255,255,.55)', fontSize: 12, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 },
};

export default Navigation;
