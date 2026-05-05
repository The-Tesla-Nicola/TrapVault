import React from 'react';
import { Account } from '../types';

interface Props { accounts: Account[]; }

const AccountSummary: React.FC<Props> = ({ accounts }) => {
  const fmt = (n: number) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n);
  const total = accounts.reduce((s, a) => s + a.balance, 0);
  const s = styles;

  return (
    <div>
      {/* Net worth banner */}
      <div style={s.banner}>
        <div>
          <div style={s.bannerLabel}>Total Portfolio Value</div>
          <div style={s.bannerValue}>{fmt(total)}</div>
          <div style={s.bannerChange}>↑ +$1,847.23 (+2.4%) this month</div>
        </div>
        <div style={s.bannerBadge}>
          <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
          FDIC Insured
        </div>
      </div>

      {/* Account cards */}
      <div style={s.grid}>
        {accounts.map(acc => (
          <div key={acc.id} style={{ ...s.card, ...(acc.type === 'checking' ? s.cardBlue : acc.type === 'savings' ? s.cardGreen : s.cardPurple) }}>
            <div style={s.cardTop}>
              <div>
                <div style={s.cardType}>{acc.type.charAt(0).toUpperCase() + acc.type.slice(1)}</div>
                <div style={s.cardName}>{acc.name}</div>
              </div>
              <div style={s.cardEmoji}>{acc.type === 'checking' ? '🏦' : acc.type === 'savings' ? '💰' : '📈'}</div>
            </div>
            <div style={s.cardBalance}>{fmt(acc.balance)}</div>
            <div style={s.cardNum}>{acc.number}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  banner: { background: 'linear-gradient(135deg,#0a2540 0%,#1a3a6b 100%)', borderRadius: 14, padding: '24px 28px', marginBottom: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', color: '#fff' },
  bannerLabel: { fontSize: 12, color: 'rgba(255,255,255,.6)', marginBottom: 6, fontWeight: 500 },
  bannerValue: { fontSize: 36, fontWeight: 800, letterSpacing: '-1px' },
  bannerChange: { fontSize: 12, color: '#34d399', marginTop: 6 },
  bannerBadge: { display: 'flex', alignItems: 'center', gap: 5, background: 'rgba(255,255,255,.1)', padding: '6px 12px', borderRadius: 20, fontSize: 11, fontWeight: 600, color: 'rgba(255,255,255,.8)' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 14 },
  card: { borderRadius: 14, padding: '18px 20px', color: '#fff', cursor: 'pointer', transition: 'transform .15s' },
  cardBlue: { background: 'linear-gradient(135deg,#1a56db,#1649c4)' },
  cardGreen: { background: 'linear-gradient(135deg,#059669,#047857)' },
  cardPurple: { background: 'linear-gradient(135deg,#7c3aed,#6d28d9)' },
  cardTop: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 },
  cardType: { fontSize: 10, fontWeight: 700, textTransform: 'uppercase' as const, opacity: .7, letterSpacing: .5, marginBottom: 3 },
  cardName: { fontSize: 13, fontWeight: 700 },
  cardEmoji: { fontSize: 20 },
  cardBalance: { fontSize: 22, fontWeight: 800, letterSpacing: '-.5px', marginBottom: 6 },
  cardNum: { fontSize: 11, opacity: .6, fontFamily: 'monospace', letterSpacing: 1 },
};

export default AccountSummary;
