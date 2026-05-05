import React, { useState, FormEvent, useEffect } from 'react';
import client from '../api/client';
import { User, AuthResponse } from '../types';

interface Props { onLogin: (user: User) => void; }

const LoginPage: React.FC<Props> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [forgotOpen, setForgotOpen] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSent, setForgotSent] = useState(false);
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    const tick = () => setCurrentTime(new Date().toLocaleTimeString());
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { data } = await client.post<AuthResponse>('/auth/login/', { username, password });
      if (data.status === 'success' || data.access_token) {
        localStorage.setItem('hp_token', data.access_token);
        if (data.refresh_token) localStorage.setItem('hp_refresh', data.refresh_token);

        // If the backend specifies a specific redirect (like the real site)
        if (data.redirect === 'L3JlYWwtc2l0ZS8=') {
          window.location.href = '/L3JlYWwtc2l0ZS8=';
          return;
        }

        onLogin(data.user);
      } else {

        setError(data.message || 'Authentication failed. Please verify your credentials.');
      }
    } catch (err: any) {
      const status = err.response?.status;
      const msg = err.response?.data?.message;
      if (status === 429) {
        setError('Account temporarily restricted. Please try again in 60 seconds.');
      } else if (status === 401) {
        setError('Invalid Member ID or Password. Please try again.');
      } else if (status === 500) {
        setError(msg || 'A system error occurred. Please try again.');
      } else {
        setError(msg || 'Connection error. Please check your network and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleForgot = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await client.post('/password-reset/', { email: forgotEmail });
    } catch {}
    setForgotSent(true);
  };

  const s = styles;

  return (
    <div style={s.root}>
      {/* Background pattern */}
      <div style={s.bgPattern}/>

      {/* TOP BAR */}
      <div style={s.topBar}>
        <div style={s.topBarInner}>
          <div style={s.brand}>
            <div style={s.brandIcon}>
              <svg width="20" height="20" fill="none" stroke="white" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4V10z"/>
              </svg>
            </div>
            <div>
              <div style={s.brandName}>SecureBank</div>
              <div style={s.brandSub}>Member FDIC · Equal Housing Lender</div>
            </div>
          </div>
          <div style={s.topBarRight}>
            <a href="#" style={s.topLink}>Personal</a>
            <a href="#" style={s.topLink}>Business</a>
            <a href="#" style={s.topLink}>Wealth</a>
            <a href="#" style={s.topLink}>About</a>
            <span style={s.topTime}>{currentTime}</span>
          </div>
        </div>
      </div>

      {/* MAIN */}
      <div style={s.main}>
        {/* LEFT panel */}
        <div style={s.left}>
          <div style={s.leftContent}>
            <div style={s.leftBadge}>🔒 Bank-Level Security</div>
            <h1 style={s.leftH1}>
              Banking designed<br/>
              <span style={s.leftAccent}>for you.</span>
            </h1>
            <p style={s.leftSub}>
              Secure, fast, and always available — access your accounts from anywhere, anytime with confidence.
            </p>
            <div style={s.features}>
              {[
                { icon: '🛡️', title: '256-bit SSL Encryption', desc: 'Your data is always protected' },
                { icon: '⚡', title: 'Instant Transfers', desc: 'Move money in seconds' },
                { icon: '📱', title: 'Mobile & Desktop', desc: 'Bank anywhere, any device' },
                { icon: '💬', title: '24/7 Support', desc: 'Help whenever you need it' },
              ].map(f => (
                <div key={f.title} style={s.featureItem}>
                  <span style={s.featureIcon}>{f.icon}</span>
                  <div>
                    <div style={s.featureTitle}>{f.title}</div>
                    <div style={s.featureDesc}>{f.desc}</div>
                  </div>
                </div>
              ))}
            </div>
            <div style={s.leftStats}>
              {[
                { val: '$2.4B+', label: 'Assets under management' },
                { val: '500K+', label: 'Active customers' },
                { val: '99.99%', label: 'Uptime SLA' },
              ].map(st => (
                <div key={st.val} style={s.stat}>
                  <div style={s.statVal}>{st.val}</div>
                  <div style={s.statLabel}>{st.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT: Login card */}
        <div style={s.right}>
          <div style={s.card}>
            <div style={s.cardHeader}>
              <h2 style={s.cardTitle}>Sign In</h2>
              <p style={s.cardSub}>Welcome back. Please enter your credentials.</p>
            </div>

            {!forgotOpen ? (
              <form onSubmit={handleSubmit} style={s.form}>
                <div style={s.field}>
                  <label style={s.label}>Member ID / Username</label>
                  <div style={s.inputWrap}>
                    <svg style={s.inputIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                    </svg>
                    <input
                      type="text"
                      value={username}
                      onChange={e => setUsername(e.target.value)}
                      style={s.input}
                      placeholder="Enter your Member ID"
                      required
                      autoComplete="username"
                    />
                  </div>
                </div>

                <div style={s.field}>
                  <div style={s.labelRow}>
                    <label style={s.label}>Password</label>
                    <button type="button" style={s.forgotBtn} onClick={() => setForgotOpen(true)}>Forgot password?</button>
                  </div>
                  <div style={s.inputWrap}>
                    <svg style={s.inputIcon} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    <input
                      type="password"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      style={s.input}
                      placeholder="••••••••••••"
                      required
                      autoComplete="current-password"
                    />
                  </div>
                </div>

                {error && (
                  <div style={s.errorBox}>
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" style={{flexShrink:0}}>
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>
                    <span>{error}</span>
                  </div>
                )}

                <button type="submit" style={{ ...s.submitBtn, opacity: loading ? .7 : 1 }} disabled={loading}>
                  {loading ? (
                    <span style={s.loadingRow}>
                      <span style={s.spinner}/>
                      Authenticating…
                    </span>
                  ) : 'Sign In Securely'}
                </button>

                <div style={s.divider}><span style={s.dividerText}>or</span></div>

                <button type="button" style={s.openAccountBtn} onClick={() => { /* honeypot trap */ client.post('/admin/users/', {}).catch(() => {}); }}>
                  Open New Account
                </button>

                <div style={s.securityNote}>
                  <svg width="14" height="14" fill="none" stroke="#6b7280" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                  </svg>
                  <span>Protected by SecureBank Multi-Factor Authentication</span>
                </div>
              </form>
            ) : (
              <div style={s.form}>
                {!forgotSent ? (
                  <>
                    <p style={{ color: '#6b7280', fontSize: 14, marginBottom: 20, lineHeight: 1.6 }}>
                      Enter your registered email address and we'll send you instructions to reset your password.
                    </p>
                    <form onSubmit={handleForgot}>
                      <div style={s.field}>
                        <label style={s.label}>Email Address</label>
                        <input type="email" value={forgotEmail} onChange={e => setForgotEmail(e.target.value)}
                          style={{...s.input, paddingLeft:14}} placeholder="your@email.com" required/>
                      </div>
                      <button type="submit" style={s.submitBtn}>Send Reset Instructions</button>
                    </form>
                    <button style={s.backBtn} onClick={() => setForgotOpen(false)}>← Back to Sign In</button>
                  </>
                ) : (
                  <div style={s.successBox}>
                    <div style={{ fontSize: 40, marginBottom: 12 }}>✉️</div>
                    <h3 style={{ fontWeight: 700, marginBottom: 8, color: '#111827' }}>Check your inbox</h3>
                    <p style={{ color: '#6b7280', fontSize: 14 }}>We've sent reset instructions to <strong>{forgotEmail}</strong></p>
                    <button style={{ ...s.submitBtn, marginTop: 20 }} onClick={() => { setForgotOpen(false); setForgotSent(false); }}>Back to Sign In</button>
                  </div>
                )}
              </div>
            )}

            <div style={s.cardFooter}>
              <div style={s.footerRow}>
                <a href="#" style={s.footerLink}>Privacy Policy</a>
                <span style={s.footerDot}>•</span>
                <a href="#" style={s.footerLink}>Terms of Service</a>
                <span style={s.footerDot}>•</span>
                <a href="#" style={s.footerLink}>Security Center</a>
              </div>
              <div style={s.fdic}>FDIC Insured · Deposits protected up to $250,000</div>
            </div>
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <div style={s.footer}>
        <div style={s.footerInner}>
          <span>© 2024 SecureBank Financial Services, N.A. All rights reserved.</span>
          <span>Member FDIC · Equal Housing Lender · NMLS #123456</span>
        </div>
      </div>
    </div>
  );
};

const C = {
  navy: '#0a2540',
  blue: '#1a56db',
  blueHover: '#1649c4',
  blueLight: '#dbeafe',
  gray50: '#f9fafb',
  gray100: '#f3f4f6',
  gray200: '#e5e7eb',
  gray400: '#9ca3af',
  gray500: '#6b7280',
  gray700: '#374151',
  gray900: '#111827',
  red: '#dc2626',
  redLight: '#fef2f2',
  green: '#059669',
  greenLight: '#ecfdf5',
};

const styles: Record<string, React.CSSProperties> = {
  root: { minHeight: '100vh', display: 'flex', flexDirection: 'column', background: C.gray50, fontFamily: "'Inter', 'IBM Plex Sans', system-ui, sans-serif" },
  bgPattern: {
    position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none',
    backgroundImage: 'radial-gradient(circle at 20% 50%, rgba(26,86,219,.04) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(10,37,64,.06) 0%, transparent 50%)',
  },
  topBar: { background: C.navy, color: '#fff', position: 'relative', zIndex: 10 },
  topBarInner: { maxWidth: 1200, margin: '0 auto', padding: '12px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  brand: { display: 'flex', alignItems: 'center', gap: 12 },
  brandIcon: { width: 40, height: 40, borderRadius: 8, background: C.blue, display: 'flex', alignItems: 'center', justifyContent: 'center' },
  brandName: { fontSize: 18, fontWeight: 700, color: '#fff' },
  brandSub: { fontSize: 10, color: 'rgba(255,255,255,.5)', letterSpacing: .3 },
  topBarRight: { display: 'flex', alignItems: 'center', gap: 24 },
  topLink: { color: 'rgba(255,255,255,.7)', textDecoration: 'none', fontSize: 13, fontWeight: 500 },
  topTime: { fontSize: 12, color: 'rgba(255,255,255,.4)', fontFamily: 'monospace' },
  main: { flex: 1, display: 'flex', maxWidth: 1200, margin: '0 auto', width: '100%', padding: '48px 24px', gap: 64, alignItems: 'flex-start', position: 'relative', zIndex: 1 },
  left: { flex: 1, paddingTop: 16 },
  leftContent: { maxWidth: 480 },
  leftBadge: { display: 'inline-block', background: C.blueLight, color: C.blue, padding: '6px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600, marginBottom: 24 },
  leftH1: { fontSize: 44, fontWeight: 800, color: C.navy, lineHeight: 1.1, marginBottom: 20 },
  leftAccent: { color: C.blue },
  leftSub: { fontSize: 17, color: C.gray500, lineHeight: 1.7, marginBottom: 36 },
  features: { display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 40 },
  featureItem: { display: 'flex', alignItems: 'center', gap: 16 },
  featureIcon: { fontSize: 22, width: 44, height: 44, background: '#fff', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 1px 4px rgba(0,0,0,.08)', flexShrink: 0 },
  featureTitle: { fontSize: 14, fontWeight: 600, color: C.gray900 },
  featureDesc: { fontSize: 13, color: C.gray500 },
  leftStats: { display: 'flex', gap: 32, padding: '24px 0', borderTop: `1px solid ${C.gray200}` },
  stat: {},
  statVal: { fontSize: 22, fontWeight: 800, color: C.navy },
  statLabel: { fontSize: 12, color: C.gray400, marginTop: 2 },
  right: { width: 420, flexShrink: 0 },
  card: { background: '#fff', borderRadius: 16, boxShadow: '0 4px 24px rgba(0,0,0,.08), 0 1px 4px rgba(0,0,0,.04)', overflow: 'hidden' },
  cardHeader: { padding: '28px 32px 0', marginBottom: 24 },
  cardTitle: { fontSize: 22, fontWeight: 800, color: C.gray900, marginBottom: 6 },
  cardSub: { fontSize: 14, color: C.gray500 },
  form: { padding: '0 32px' },
  field: { marginBottom: 18 },
  labelRow: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 },
  label: { fontSize: 13, fontWeight: 600, color: C.gray700, display: 'block', marginBottom: 6 },
  forgotBtn: { background: 'none', border: 'none', color: C.blue, fontSize: 13, cursor: 'pointer', fontWeight: 500 },
  inputWrap: { position: 'relative' },
  inputIcon: { position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', width: 18, height: 18, stroke: C.gray400 } as React.CSSProperties,
  input: {
    width: '100%', padding: '11px 14px 11px 40px', border: `1.5px solid ${C.gray200}`,
    borderRadius: 10, fontSize: 14, color: C.gray900, outline: 'none',
    transition: 'border-color .15s', boxSizing: 'border-box' as const, background: '#fff',
  },
  errorBox: {
    background: C.redLight, border: `1px solid #fecaca`, borderRadius: 10, padding: '10px 14px',
    color: C.red, fontSize: 13, marginBottom: 16, display: 'flex', alignItems: 'flex-start', gap: 8,
  },
  submitBtn: {
    width: '100%', padding: '13px', background: C.blue, border: 'none', borderRadius: 10,
    color: '#fff', fontSize: 15, fontWeight: 600, cursor: 'pointer', transition: 'background .15s',
    marginBottom: 14,
  },
  divider: { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 },
  dividerText: { fontSize: 12, color: C.gray400, background: '#fff', padding: '0 8px' },
  openAccountBtn: {
    width: '100%', padding: '12px', background: '#fff', border: `1.5px solid ${C.gray200}`,
    borderRadius: 10, color: C.gray700, fontSize: 14, fontWeight: 600, cursor: 'pointer',
    marginBottom: 20, transition: 'border-color .15s',
  },
  securityNote: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: C.gray400, marginBottom: 24, justifyContent: 'center' },
  cardFooter: { background: C.gray50, borderTop: `1px solid ${C.gray100}`, padding: '16px 32px', textAlign: 'center' as const },
  footerRow: { display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, marginBottom: 6 },
  footerLink: { fontSize: 12, color: C.gray500, textDecoration: 'none' },
  footerDot: { color: C.gray200, fontSize: 12 },
  fdic: { fontSize: 11, color: C.gray400 },
  footer: { background: C.navy, color: 'rgba(255,255,255,.4)', padding: '16px 24px', position: 'relative', zIndex: 1 },
  footerInner: { maxWidth: 1200, margin: '0 auto', display: 'flex', justifyContent: 'space-between', fontSize: 12 },
  loadingRow: { display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' },
  spinner: { width: 16, height: 16, border: '2px solid rgba(255,255,255,.3)', borderTop: '2px solid #fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite', display: 'inline-block' },
  backBtn: { background: 'none', border: 'none', color: C.blue, fontSize: 13, cursor: 'pointer', marginTop: 12, fontWeight: 500 },
  successBox: { textAlign: 'center' as const, padding: '20px 0' },
};

export default LoginPage;
