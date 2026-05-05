import React, { useState } from 'react';
import { Transaction } from '../types';

interface Props { transactions: Transaction[]; }

const ICONS: Record<string, string> = {
  Income: '💼', Shopping: '🛍️', Groceries: '🛒', Utilities: '💡',
  Dining: '☕', Entertainment: '🎬', Interest: '💹', Transportation: '⛽',
  Transfer: '🔄', Healthcare: '🏥', Insurance: '🛡️', Other: '📋',
};

const TransactionHistory: React.FC<Props> = ({ transactions }) => {
  const [search, setSearch] = useState('');
  const fmt = (n: number) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);
  const fmtDate = (s: string) => new Date(s).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

  const filtered = transactions.filter(t =>
    t.description.toLowerCase().includes(search.toLowerCase()) ||
    (t.category||'').toLowerCase().includes(search.toLowerCase())
  );

  const s = styles;
  return (
    <div style={s.wrap}>
      <div style={s.header}>
        <h3 style={s.title}>Recent Transactions</h3>
        <div style={s.searchWrap}>
          <svg style={s.searchIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <input style={s.search} placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)}/>
        </div>
      </div>
      <div>
        {filtered.length === 0 && <div style={s.empty}>No transactions found</div>}
        {filtered.map(t => (
          <div key={t.id} style={s.row}>
            <div style={{ ...s.icon, background: t.type === 'credit' ? '#ecfdf5' : '#fff7ed' }}>
              {ICONS[t.category || 'Other'] || '📋'}
            </div>
            <div style={s.mid}>
              <div style={s.desc}>{t.description}</div>
              <div style={s.meta}>{fmtDate(t.date)} · {t.category || 'Other'}</div>
            </div>
            <div>
              <div style={{ ...s.amt, color: t.type === 'credit' ? '#059669' : '#374151' }}>
                {t.type === 'credit' ? '+' : '−'}{fmt(t.amount)}
              </div>
              <div style={{ ...s.status, background: t.status === 'completed' ? '#ecfdf5' : '#fef3c7', color: t.status === 'completed' ? '#059669' : '#d97706' }}>
                {t.status}
              </div>
            </div>
          </div>
        ))}
      </div>
      {filtered.length > 0 && (
        <div style={s.footer}>
          <button style={s.moreBtn}>View All Transactions →</button>
        </div>
      )}
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  wrap: { background: '#fff', borderRadius: 14, border: '1px solid #e5e7eb', overflow: 'hidden' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '18px 20px', borderBottom: '1px solid #f3f4f6' },
  title: { fontSize: 15, fontWeight: 700, color: '#111827', margin: 0 },
  searchWrap: { position: 'relative' },
  searchIcon: { position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 16, height: 16, stroke: '#9ca3af' } as React.CSSProperties,
  search: { padding: '7px 12px 7px 32px', border: '1px solid #e5e7eb', borderRadius: 8, fontSize: 13, outline: 'none', width: 200 },
  row: { display: 'flex', alignItems: 'center', gap: 12, padding: '13px 20px', borderBottom: '1px solid #f9fafb' },
  icon: { width: 40, height: 40, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 17, flexShrink: 0 },
  mid: { flex: 1, minWidth: 0 },
  desc: { fontSize: 13, fontWeight: 500, color: '#111827', whiteSpace: 'nowrap' as const, overflow: 'hidden', textOverflow: 'ellipsis' },
  meta: { fontSize: 11, color: '#9ca3af', marginTop: 2 },
  amt: { fontSize: 14, fontWeight: 700, textAlign: 'right' as const },
  status: { fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 20, marginTop: 3, textAlign: 'center' as const, textTransform: 'capitalize' as const },
  footer: { padding: '14px 20px', borderTop: '1px solid #f3f4f6', textAlign: 'center' as const },
  moreBtn: { background: 'none', border: 'none', color: '#1a56db', fontSize: 13, fontWeight: 600, cursor: 'pointer' },
  empty: { padding: '32px', textAlign: 'center' as const, color: '#9ca3af', fontSize: 13 },
};

export default TransactionHistory;
