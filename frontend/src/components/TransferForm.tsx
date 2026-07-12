import React, { useState, FormEvent } from 'react';
import client from '../api/client';

const ACCOUNTS = [
  { id: 'chk', name: 'Premier Checking', balance: '$12,847.53' },
  { id: 'sav', name: 'High-Yield Savings', balance: '$31,205.00' },
];

const TransferForm: React.FC = () => {
  const [from, setFrom] = useState('chk');
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [note, setNote] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'done'>('idle');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setStatus('loading');
    // Fire to deception endpoint — SIEM logs this interaction
    try { await client.post('/search/', { q: `transfer_${amount}_to_${to}` }); } catch { /* ignored */ }
    setTimeout(() => setStatus('done'), 1400);
  };

  const s = styles;
  if (status === 'done') return (
    <div style={s.success}>
      <div style={s.successIcon}>✅</div>
      <h3 style={s.successTitle}>Transfer Submitted</h3>
      <p style={s.successMsg}>Your transfer of ${amount} has been queued for processing. Funds typically arrive within 1–3 business days.</p>
      <button style={s.resetBtn} onClick={() => { setStatus('idle'); setAmount(''); setTo(''); setNote(''); }}>New Transfer</button>
    </div>
  );

  return (
    <div style={s.wrap}>
      <h3 style={s.title}>Send Money / Wire Transfer</h3>
      <form onSubmit={handleSubmit}>
        <div style={s.field}>
          <label style={s.label}>From Account</label>
          <select style={s.input} value={from} onChange={e => setFrom(e.target.value)}>
            {ACCOUNTS.map(a => <option key={a.id} value={a.id}>{a.name} — {a.balance}</option>)}
          </select>
        </div>
        <div style={s.field}>
          <label style={s.label}>To (Account / Recipient)</label>
          <input style={s.input} value={to} onChange={e => setTo(e.target.value)} placeholder="Account number, email, or phone" required/>
        </div>
        <div style={s.field}>
          <label style={s.label}>Amount</label>
          <div style={{ position: 'relative' }}>
            <span style={s.dollar}>$</span>
            <input style={{ ...s.input, paddingLeft: 26 }} type="number" min="0.01" step="0.01" value={amount} onChange={e => setAmount(e.target.value)} placeholder="0.00" required/>
          </div>
        </div>
        <div style={s.field}>
          <label style={s.label}>Note (optional)</label>
          <input style={s.input} value={note} onChange={e => setNote(e.target.value)} placeholder="What's this for?"/>
        </div>
        <div style={s.notice}>⚠ Daily transfer limit: $10,000. Review before confirming.</div>
        <button type="submit" style={{ ...s.btn, opacity: status === 'loading' ? .7 : 1 }} disabled={status === 'loading'}>
          {status === 'loading' ? 'Processing…' : 'Confirm Transfer'}
        </button>
      </form>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  wrap: { background: '#fff', borderRadius: 14, border: '1px solid #e5e7eb', padding: 24 },
  title: { fontSize: 15, fontWeight: 700, color: '#111827', marginBottom: 20, margin: '0 0 20px' },
  field: { marginBottom: 16 },
  label: { display: 'block', fontSize: 12, fontWeight: 600, color: '#374151', marginBottom: 6 },
  input: { width: '100%', padding: '10px 12px', border: '1.5px solid #e5e7eb', borderRadius: 10, fontSize: 13, color: '#111827', outline: 'none', boxSizing: 'border-box' as const, background: '#fff' },
  dollar: { position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#6b7280', fontWeight: 600 },
  notice: { background: '#fefce8', border: '1px solid #fde68a', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: '#92400e', marginBottom: 16 },
  btn: { width: '100%', padding: 13, background: '#1a56db', border: 'none', borderRadius: 10, color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer' },
  success: { background: '#fff', borderRadius: 14, border: '1px solid #e5e7eb', padding: 32, textAlign: 'center' as const },
  successIcon: { fontSize: 44, marginBottom: 12 },
  successTitle: { fontWeight: 700, fontSize: 18, color: '#111827', marginBottom: 8, margin: '0 0 8px' },
  successMsg: { color: '#6b7280', fontSize: 13, lineHeight: 1.6, margin: '0 0 20px' },
  resetBtn: { padding: '10px 24px', border: '1.5px solid #1a56db', borderRadius: 10, background: 'none', color: '#1a56db', fontWeight: 600, fontSize: 13, cursor: 'pointer' },
};

export default TransferForm;
