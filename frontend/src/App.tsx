import { useState, useEffect, useRef } from 'react'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import { User } from './types'
import axios from 'axios'

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const activityBuffer = useRef<any[]>([])

  // --- SENSOR SUITE: Attacker Telemetry ---
  useEffect(() => {
    // Only run sensors on the public-facing decoy (when not logged in as monitor)
    const isMonitor = !!localStorage.getItem('hp_token')
    if (isMonitor) return;

    const captureActivity = (event: string, data: any, element?: HTMLElement) => {
      activityBuffer.current.push({
        event_type: event,
        data: data,
        path: window.location.pathname,
        element_id: element?.id || element?.className || '',
        timestamp: new Date().toISOString()
      });

      // Flush buffer if it gets too large
      if (activityBuffer.current.length >= 20) flushBuffer();
    };

    const flushBuffer = async () => {
      if (activityBuffer.current.length === 0) return;
      const payload = [...activityBuffer.current];
      activityBuffer.current = [];
      try {
        // Send to the silent telemetry endpoint
        await axios.post('/api/telemetry/capture/', { activities: payload });
      } catch (e) { /* silent fail */ }
    };

    // Listeners
    const onKey = (e: KeyboardEvent) => captureActivity('keystroke', { key: e.key, code: e.code }, e.target as HTMLElement);
    const onClick = (e: MouseEvent) => captureActivity('click', { x: e.clientX, y: e.clientY }, e.target as HTMLElement);
    const onMove = (e: MouseEvent) => {
      // Throttle mouse moves to every 200ms
      if (Math.random() > 0.95) { // Simple sampling for now
        captureActivity('mouse_move', { x: e.clientX, y: e.clientY }, e.target as HTMLElement);
      }
    };

    window.addEventListener('keydown', onKey);
    window.addEventListener('mousedown', onClick);
    window.addEventListener('mousemove', onMove);

    // Periodic flush
    const interval = setInterval(flushBuffer, 10000);

    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('mousedown', onClick);
      window.removeEventListener('mousemove', onMove);
      clearInterval(interval);
      flushBuffer();
    };
  }, []);
  // --- END SENSOR SUITE ---

  useEffect(() => {
    const token = localStorage.getItem('hp_token')
    const savedUser = localStorage.getItem('hp_user')
    if (token && savedUser) {
      try { setUser(JSON.parse(savedUser)) }
      catch { localStorage.removeItem('hp_token'); localStorage.removeItem('hp_user') }
    }
    setLoading(false)
  }, [])

  const handleLogin = (userData: User) => {
    setUser(userData)
    localStorage.setItem('hp_user', JSON.stringify(userData))
  }

  const handleLogout = () => {
    localStorage.removeItem('hp_token')
    localStorage.removeItem('hp_user')
    localStorage.removeItem('hp_refresh')
    setUser(null)
  }

  if (loading) return (
    <div style={{ minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',background:'#f9fafb',flexDirection:'column',gap:16 }}>
      <div style={{ width:44,height:44,borderRadius:8,background:'#1a56db',display:'flex',alignItems:'center',justifyContent:'center',animation:'pulse 1.5s infinite' }}>
        <svg width="22" height="22" fill="none" stroke="white" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 14v3m4-3v3m4-3v3M3 21h18M3 10h18M3 7l9-4 9 4M4 10h16v11H4V10z"/>
        </svg>
      </div>
      <div style={{ color:'#1a56db',fontWeight:600,fontSize:15,fontFamily:'system-ui' }}>Establishing Secure Connection…</div>
    </div>
  )

  return user
    ? <DashboardPage user={user} onLogout={handleLogout}/>
    : <LoginPage onLogin={handleLogin}/>
}

export default App
