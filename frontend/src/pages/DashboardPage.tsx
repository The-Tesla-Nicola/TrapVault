import React, { useState, useEffect } from 'react';
import { User, Transaction, Account } from '../types';
import Navigation from '../components/Navigation';
import AccountSummary from '../components/AccountSummary';
import TransactionHistory from '../components/TransactionHistory';
import TransferForm from '../components/TransferForm';
import client from '../api/client';

interface Props { user: User; onLogout: () => void; }

const ACCOUNTS: Account[] = [
  { id: 'chk', name: 'Premier Checking', number: '****4892', balance: 12847.53, type: 'checking', currency: 'USD' },
  { id: 'sav', name: 'High-Yield Savings', number: '****2107', balance: 31205.00, type: 'savings', currency: 'USD' },
  { id: 'inv', name: 'Investment Portfolio', number: '****8834', balance: 87435.20, type: 'investment', currency: 'USD' },
];

const TRANSACTIONS: Transaction[] = [
  { id: '1', date: '2024-03-28', description: 'Direct Deposit — PAYROLL ACME CORP', amount: 5250.00, type: 'credit', status: 'completed', category: 'Income' },
  { id: '2', date: '2024-03-27', description: 'Amazon.com Marketplace', amount: 127.84, type: 'debit', status: 'completed', category: 'Shopping' },
  { id: '3', date: '2024-03-27', description: 'Whole Foods Market #441', amount: 89.23, type: 'debit', status: 'completed', category: 'Groceries' },
  { id: '4', date: '2024-03-26', description: 'AT&T Monthly Bill', amount: 185.00, type: 'debit', status: 'completed', category: 'Utilities' },
  { id: '5', date: '2024-03-26', description: 'Transfer to Savings Account', amount: 1000.00, type: 'debit', status: 'completed', category: 'Transfer' },
  { id: '6', date: '2024-03-25', description: 'Starbucks Reserve #4421', amount: 14.80, type: 'debit', status: 'completed', category: 'Dining' },
  { id: '7', date: '2024-03-24', description: 'Netflix Subscription', amount: 22.99, type: 'debit', status: 'completed', category: 'Entertainment' },
  { id: '8', date: '2024-03-24', description: 'Interest Payment — HYSA', amount: 62.41, type: 'credit', status: 'completed', category: 'Interest' },
  { id: '9', date: '2024-03-23', description: 'Shell Gas Station #2441', amount: 61.15, type: 'debit', status: 'completed', category: 'Transportation' },
  { id: '10', date: '2024-03-22', description: 'Venmo Transfer Received', amount: 250.00, type: 'credit', status: 'completed', category: 'Transfer' },
  { id: '11', date: '2024-03-21', description: 'Delta Airlines Flight', amount: 498.00, type: 'debit', status: 'completed', category: 'Transportation' },
  { id: '12', date: '2024-03-20', description: 'Blue Cross Insurance', amount: 420.00, type: 'debit', status: 'completed', category: 'Healthcare' },
];

type Tab = 'overview' | 'accounts' | 'transfer' | 'admin' | 'settings';

const DashboardPage: React.FC<Props> = ({ user, onLogout }) => {
  const [tab, setTab] = useState<Tab>('overview');
  const [adminQuery, setAdminQuery] = useState('');
  const [adminResult, setAdminResult] = useState<string | null>(null);
  const [adminLoading, setAdminLoading] = useState(false);
  const [clock, setClock] = useState('');
  const fmt = (n: number) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  const handleAdminQuery = async () => {
    if (!adminQuery.trim()) return;
    setAdminLoading(true);
    try {
      // All these fire to honeypot deception endpoints — SIEM logs everything
      const res = await client.post('/admin/database/', { query: adminQuery });
      setAdminResult(JSON.stringify(res.data, null, 2));
    } catch (e: any) {
      setAdminResult(e.response?.data ? JSON.stringify(e.response.data, null, 2) : 'Error: Connection refused');
    }
    setAdminLoading(false);
  };

  const fireHoneypot = (endpoint: string) => {
    client.get(endpoint).catch(() => {});
  };

  const s = styles;

  return (
    <div style={s.root}>
      <Navigation user={user} onLogout={onLogout} activeTab={tab} onTabChange={(t) => setTab(t as Tab)}/>

      <main style={s.main}>
        {/* Topbar */}
        <div style={s.topbar}>
          <div>
            <h1 style={s.pageTitle}>
              {tab === 'overview' && 'Account Overview'}
              {tab === 'accounts' && 'My Accounts'}
              {tab === 'transfer' && 'Transfers & Payments'}
              {tab === 'admin' && 'Administration Panel'}
              {tab === 'settings' && 'Account Settings'}
            </h1>
            <div style={s.pageSub}>{new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div>
          </div>
          <div style={s.topbarRight}>
            <div style={s.clockBadge}>{clock}</div>
            <button style={s.notifBtn} title="Notifications">
              <svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/>
              </svg>
              <span style={s.notifDot}/>
            </button>
            <div style={s.secureBadge}>🔒 256-bit TLS</div>
          </div>
        </div>

        <div style={s.content}>
          {/* ══ OVERVIEW ══ */}
          {tab === 'overview' && (
            <div>
              <AccountSummary accounts={ACCOUNTS}/>
              <div style={{ marginTop: 20 }}>
                <TransactionHistory transactions={TRANSACTIONS}/>
              </div>
            </div>
          )}

          {/* ══ ACCOUNTS ══ */}
          {tab === 'accounts' && (
            <div>
              {ACCOUNTS.map(acc => (
                <div key={acc.id} style={s.acctCard}>
                  <div style={s.acctCardHeader}>
                    <div>
                      <div style={s.acctType}>{acc.type.charAt(0).toUpperCase() + acc.type.slice(1)} Account</div>
                      <div style={s.acctName}>{acc.name}</div>
                      <div style={s.acctNum}>Account {acc.number} · Routing ****7281</div>
                    </div>
                    <div style={s.acctBal}>{fmt(acc.balance)}</div>
                  </div>
                  <div style={s.acctStats}>
                    {[
                      { label: 'Available Balance', val: fmt(acc.balance * .98) },
                      { label: 'Pending Transactions', val: fmt(acc.balance * .02) },
                      { label: 'Interest Rate', val: acc.type === 'savings' ? '2.50% APY' : acc.type === 'investment' ? '+8.2% YTD' : 'N/A' },
                      { label: 'Statement Date', val: '1st of month' },
                    ].map(it => (
                      <div key={it.label}>
                        <div style={s.statLabel}>{it.label}</div>
                        <div style={s.statVal}>{it.val}</div>
                      </div>
                    ))}
                  </div>
                  <div style={s.acctActions}>
                    <button style={s.acctBtn} onClick={() => setTab('transfer')}>Transfer</button>
                    <button style={s.acctBtn} onClick={() => fireHoneypot('/admin/download/?file=statement.pdf')}>Statement</button>
                    <button style={s.acctBtn} onClick={() => fireHoneypot('/admin/backup/')}>Full Details</button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ══ TRANSFER ══ */}
          {tab === 'transfer' && (
            <div style={s.transferGrid}>
              <TransferForm/>
              <div>
                <div style={s.sectionCard}>
                  <h4 style={s.sectionTitle}>Recent Transfers</h4>
                  <TransactionHistory transactions={TRANSACTIONS.filter(t => t.category === 'Transfer')}/>
                </div>
                <div style={s.limitCard}>
                  <div style={s.limitTitle}>Transfer Limits</div>
                  {[
                    { label: 'Daily ACH', used: 1000, max: 10000 },
                    { label: 'Daily Wire', used: 0, max: 50000 },
                    { label: 'Monthly', used: 4250, max: 100000 },
                  ].map(l => (
                    <div key={l.label} style={{ marginBottom: 14 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                        <span style={{ color: '#374151', fontWeight: 500 }}>{l.label}</span>
                        <span style={{ color: '#6b7280' }}>{fmt(l.used)} / {fmt(l.max)}</span>
                      </div>
                      <div style={{ height: 6, background: '#f3f4f6', borderRadius: 6, overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${(l.used / l.max) * 100}%`, background: '#1a56db', borderRadius: 6 }}/>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ══ ADMIN PANEL (honeypot) ══ */}
          {tab === 'admin' && (
            <div>
              <div style={s.adminAlert}>
                <span style={{ fontSize: 18 }}>⚠</span>
                <div>
                  <strong>Restricted Access — Administrator Only</strong>
                  <div style={{ fontSize: 12, marginTop: 2 }}>All actions in this panel are logged and audited. Unauthorised use is prohibited and will result in immediate account suspension.</div>
                </div>
              </div>

              <div style={s.adminGrid}>
                {[
                  { title: 'User Management', desc: 'View and manage customer accounts and permissions', icon: '👥', endpoint: '/admin/users/' },
                  { title: 'System Configuration', desc: 'Application settings and feature flags', icon: '⚙️', endpoint: '/admin/settings/' },
                  { title: 'Backup & Recovery', desc: 'Database backups and disaster recovery tools', icon: '💾', endpoint: '/admin/backup/' },
                  { title: 'API Key Management', desc: 'Manage internal and external API access tokens', icon: '🔑', endpoint: '/admin/api-keys/' },
                  { title: 'File Browser', desc: 'Browse and manage server filesystem', icon: '📁', endpoint: '/admin/files/' },
                  { title: 'Internal Config', desc: 'Environment variables and secrets manager', icon: '🔧', endpoint: '/internal/config/' },
                ].map(panel => (
                  <div key={panel.title} style={s.adminCard} onClick={() => fireHoneypot(panel.endpoint)}>
                    <div style={s.adminCardIcon}>{panel.icon}</div>
                    <div style={s.adminCardTitle}>{panel.title}</div>
                    <div style={s.adminCardDesc}>{panel.desc}</div>
                    <div style={s.adminCardArrow}>→</div>
                  </div>
                ))}
              </div>

              {/* Database Console — fires to /api/admin/database/ */}
              <div style={s.dbConsole}>
                <div style={s.dbConsoleHeader}>
                  <span style={{ color: '#94a3b8', fontWeight: 600, fontSize: 13 }}>🗄️ Database Console</span>
                  <span style={{ color: '#475569', fontSize: 11, fontFamily: 'monospace' }}>PostgreSQL 16 · securebank_prod</span>
                </div>
                <div style={s.dbHint}>
                  {/* Breadcrumb hidden in source — attacker reads HTML source to find this */}
                  {/* <!-- Admin backup download: /admin/download/?file=database_backup.sql.gz --> */}
                  {/* <!-- Secret admin panel: /super-secret-admin-v4/ --> */}
                  Try: SELECT * FROM bank_users LIMIT 10; or SELECT * FROM transactions WHERE amount &gt; 10000;
                </div>
                <textarea
                  style={s.dbTextarea}
                  rows={4}
                  value={adminQuery}
                  onChange={e => setAdminQuery(e.target.value)}
                  placeholder="SELECT * FROM users WHERE role = 'admin' LIMIT 10;"
                />
                <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
                  <button style={s.dbRunBtn} onClick={handleAdminQuery} disabled={adminLoading}>
                    {adminLoading ? 'Executing…' : '▶ Run Query'}
                  </button>
                  <button style={s.dbClearBtn} onClick={() => { setAdminQuery(''); setAdminResult(null); }}>Clear</button>
                  <button style={s.dbClearBtn} onClick={() => fireHoneypot('/admin/download/?file=q3_financial_unredacted.pdf')}>
                    📄 Download q3_financial_unredacted.pdf
                  </button>
                </div>
                {adminResult && (
                  <div style={s.dbResult}>
                    <pre style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{adminResult}</pre>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ══ SETTINGS ══ */}
          {tab === 'settings' && (
            <div style={s.settingsGrid}>
              {[
                { title: 'Profile Information', items: [{ label: 'Full Name', val: user.name || user.username }, { label: 'Email Address', val: user.email || 'michael@securebank.com' }, { label: 'Phone Number', val: '+1 (555) 000-0000' }, { label: 'Date of Birth', val: '●●/●●/●●●●' }] },
                { title: 'Security Settings', items: [{ label: 'Two-Factor Auth', val: '✅ Enabled (TOTP)' }, { label: 'Last Login', val: new Date().toLocaleString() }, { label: 'Login Alerts', val: 'Email + SMS' }, { label: 'Active Sessions', val: '1 device' }] },
                { title: 'Notification Preferences', items: [{ label: 'Transaction Alerts', val: 'All transactions' }, { label: 'Login Alerts', val: 'Enabled' }, { label: 'Statement Ready', val: 'Email' }, { label: 'Fraud Alerts', val: 'SMS + Email' }] },
                { title: 'Privacy & Data', items: [{ label: 'Data Sharing', val: 'Opt-out' }, { label: 'Marketing', val: 'Disabled' }, { label: 'Analytics', val: 'Functional only' }, { label: 'Download My Data', val: 'Request export →' }] },
              ].map(section => (
                <div key={section.title} style={s.settingsCard}>
                  <div style={s.settingsCardTitle}>{section.title}</div>
                  {section.items.map(it => (
                    <div key={it.label} style={s.settingsRow}>
                      <span style={s.settingsLabel}>{it.label}</span>
                      <span style={s.settingsVal}>{it.val}</span>
                    </div>
                  ))}
                  <button style={s.acctBtn} onClick={() => fireHoneypot('/admin/users/')}>Edit</button>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

const C = {
  navy: '#0a2540', blue: '#1a56db', white: '#fff',
  gray50: '#f9fafb', gray100: '#f3f4f6', gray200: '#e5e7eb',
  gray400: '#9ca3af', gray500: '#6b7280', gray700: '#374151', gray900: '#111827',
};

const styles: Record<string, React.CSSProperties> = {
  root: { display: 'flex', minHeight: '100vh', background: C.gray50, fontFamily: "'Inter','IBM Plex Sans',system-ui,sans-serif" },
  main: { flex: 1, marginLeft: 240 },
  topbar: { background: C.white, borderBottom: `1px solid ${C.gray200}`, padding: '18px 28px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 50 },
  pageTitle: { fontSize: 22, fontWeight: 800, color: C.gray900, margin: 0 },
  pageSub: { fontSize: 12, color: C.gray400, marginTop: 3 },
  topbarRight: { display: 'flex', alignItems: 'center', gap: 14 },
  clockBadge: { fontSize: 12, color: C.gray500, fontFamily: 'monospace', background: C.gray50, padding: '5px 10px', borderRadius: 8, border: `1px solid ${C.gray200}` },
  notifBtn: { position: 'relative', background: 'none', border: 'none', cursor: 'pointer', padding: 6, color: C.gray500 },
  notifDot: { position: 'absolute', top: 4, right: 4, width: 8, height: 8, background: '#dc2626', borderRadius: '50%', border: `2px solid ${C.white}` },
  secureBadge: { background: '#ecfdf5', color: '#059669', fontSize: 11, fontWeight: 600, padding: '5px 11px', borderRadius: 20, border: '1px solid #a7f3d0' },
  content: { padding: '24px 28px 40px' },
  // Accounts
  acctCard: { background: C.white, borderRadius: 14, border: `1px solid ${C.gray200}`, overflow: 'hidden', marginBottom: 18 },
  acctCardHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '20px 22px', borderBottom: `1px solid ${C.gray100}` },
  acctType: { fontSize: 10, fontWeight: 700, color: C.gray400, textTransform: 'uppercase' as const, letterSpacing: .5, marginBottom: 4 },
  acctName: { fontSize: 17, fontWeight: 700, color: C.gray900 },
  acctNum: { fontSize: 11, color: C.gray400, marginTop: 3, fontFamily: 'monospace' },
  acctBal: { fontSize: 28, fontWeight: 800, color: C.gray900 },
  acctStats: { display: 'flex', gap: 36, padding: '14px 22px', borderBottom: `1px solid ${C.gray100}` },
  statLabel: { fontSize: 10, color: C.gray400, marginBottom: 4, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: .3 },
  statVal: { fontSize: 14, fontWeight: 600, color: C.gray900 },
  acctActions: { padding: '14px 22px', display: 'flex', gap: 10 },
  acctBtn: { padding: '8px 16px', border: `1px solid ${C.gray200}`, borderRadius: 8, background: C.white, fontSize: 13, fontWeight: 500, cursor: 'pointer', color: C.gray700 },
  // Transfer
  transferGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 },
  sectionCard: { background: C.white, borderRadius: 14, border: `1px solid ${C.gray200}`, overflow: 'hidden', marginBottom: 16 },
  sectionTitle: { fontWeight: 700, fontSize: 14, color: C.gray900, padding: '14px 18px', borderBottom: `1px solid ${C.gray100}`, margin: 0 },
  limitCard: { background: C.white, borderRadius: 14, border: `1px solid ${C.gray200}`, padding: '16px 18px' },
  limitTitle: { fontWeight: 700, fontSize: 14, color: C.gray900, marginBottom: 14 },
  // Admin
  adminAlert: { background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 12, padding: '14px 18px', marginBottom: 22, display: 'flex', gap: 12, alignItems: 'flex-start', fontSize: 13, color: '#dc2626' },
  adminGrid: { display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 22 },
  adminCard: { background: C.white, borderRadius: 14, border: `1px solid ${C.gray200}`, padding: '20px', cursor: 'pointer', transition: 'all .15s', position: 'relative' },
  adminCardIcon: { fontSize: 28, marginBottom: 10 },
  adminCardTitle: { fontSize: 14, fontWeight: 700, color: C.gray900, marginBottom: 4 },
  adminCardDesc: { fontSize: 12, color: C.gray500, lineHeight: 1.5 },
  adminCardArrow: { position: 'absolute', top: 18, right: 18, color: C.gray400, fontSize: 18 },
  dbConsole: { background: '#0f172a', borderRadius: 14, padding: '20px 22px' },
  dbConsoleHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 },
  dbHint: { fontSize: 11, color: '#64748b', marginBottom: 10, fontFamily: 'monospace' },
  dbTextarea: { width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0', padding: '12px 14px', fontSize: 13, fontFamily: 'monospace', resize: 'vertical' as const, boxSizing: 'border-box' as const, outline: 'none', lineHeight: 1.6 },
  dbRunBtn: { padding: '9px 20px', background: C.blue, border: 'none', borderRadius: 8, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' },
  dbClearBtn: { padding: '9px 16px', background: 'rgba(255,255,255,.07)', border: '1px solid rgba(255,255,255,.1)', borderRadius: 8, color: '#94a3b8', fontSize: 13, cursor: 'pointer' },
  dbResult: { marginTop: 14, background: '#1e293b', borderRadius: 8, padding: '14px', color: '#a3e635', fontFamily: 'monospace', fontSize: 11, maxHeight: 260, overflowY: 'auto' },
  // Settings
  settingsGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 },
  settingsCard: { background: C.white, borderRadius: 14, border: `1px solid ${C.gray200}`, padding: '20px 22px' },
  settingsCardTitle: { fontSize: 15, fontWeight: 700, color: C.gray900, marginBottom: 16, paddingBottom: 14, borderBottom: `1px solid ${C.gray100}` },
  settingsRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: `1px solid ${C.gray100}` },
  settingsLabel: { fontSize: 13, color: C.gray500 },
  settingsVal: { fontSize: 13, fontWeight: 600, color: C.gray900 },
};

export default DashboardPage;
