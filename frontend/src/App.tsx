import { BrowserRouter, Routes, Route, Navigate, NavLink, useNavigate } from 'react-router-dom'
import {
    LayoutDashboard, Siren, FolderOpen, Cpu, BookOpen, Settings, LogOut,
    Shield, Activity, Terminal
} from 'lucide-react'
import { AuthProvider, useAuth } from './hooks/useAuth'
import Login from './pages/Login'
import AlertsPage from './pages/Alerts'
import IncidentsPage from './pages/Incidents'
import DashboardPage from './pages/Dashboard'
import RulesPage from './pages/Rules'
import SettingsPage from './pages/Settings'
import PlaybooksPage from './pages/Playbooks'

// ─── Sidebar ──────────────────────────────────────────────────────────────────
function Sidebar() {
    const { user, logout } = useAuth()
    const navigate = useNavigate()
    const handleLogout = () => { logout(); navigate('/login') }

    return (
        <div className="sidebar">
            <div className="section-label">// Monitoring</div>
            <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'active' : ''}>
                <LayoutDashboard size={15} /> Dashboard
            </NavLink>
            <NavLink to="/alerts" className={({ isActive }) => isActive ? 'active' : ''}>
                <Siren size={15} /> Alert Queue
            </NavLink>
            <NavLink to="/incidents" className={({ isActive }) => isActive ? 'active' : ''}>
                <FolderOpen size={15} /> Incidents
            </NavLink>
            <NavLink to="/playbooks" className={({ isActive }) => isActive ? 'active' : ''}>
                <Cpu size={15} /> SOAR Engine
            </NavLink>

            <div className="section-label" style={{ marginTop: 12 }}>// Operations</div>
            <NavLink to="/rules" className={({ isActive }) => isActive ? 'active' : ''}>
                <BookOpen size={15} /> Detect. Rules
            </NavLink>
            {user?.role === 'admin' && (
                <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
                    <Settings size={15} /> Config
                </NavLink>
            )}

            <div style={{ flex: 1 }} />

            {/* Operator info */}
            <div style={{
                margin: '12px 16px',
                padding: '10px 14px',
                background: 'rgba(0, 255, 136, 0.05)',
                border: '1px solid rgba(0, 255, 136, 0.15)',
                borderRadius: 4
            }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 4 }}>Operator</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--neon-green)' }}>{user?.username}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2, textTransform: 'uppercase', letterSpacing: '1px' }}>{user?.role}</div>
            </div>

            <button onClick={handleLogout} style={{ marginBottom: 8 }}>
                <LogOut size={14} /> Sign Out
            </button>
        </div>
    )
}

// ─── Topbar ───────────────────────────────────────────────────────────────────
function Topbar() {
    const { user } = useAuth()
    return (
        <div className="topbar">
            <Shield size={18} color="var(--neon-green)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-green))' }} />
            <div className="brand">
                SOC Platform
                <span>v1.0 — LIVE</span>
            </div>

            <div className="spacer" />

            {/* Status indicators */}
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Activity size={12} color="var(--neon-cyan)" />
                    THREAT MONITOR
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--neon-green)' }}>
                    <span className="live-dot" />ONLINE
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Terminal size={12} color="var(--neon-blue)" />
                    {new Date().toLocaleTimeString()}
                </span>
            </div>

            <div style={{ width: 1, height: 28, background: 'var(--border-dim)', margin: '0 8px' }} />

            {user && (
                <div className="user-pill">
                    <Shield size={12} />
                    {user.username}
                    <span className="role-badge">{user.role}</span>
                </div>
            )}
        </div>
    )
}

// ─── Protected Layout ─────────────────────────────────────────────────────────
function ProtectedLayout({ children }: { children: React.ReactNode }) {
    const { user, loading } = useAuth()
    if (loading) return (
        <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16 }}>
            <Shield size={36} color="var(--neon-green)" style={{ filter: 'drop-shadow(0 0 12px var(--neon-green))' }} />
            <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '0.82rem', letterSpacing: 2 }} className="pulse">
                AUTHENTICATING SESSION...
            </div>
        </div>
    )
    if (!user) return <Navigate to="/login" replace />
    return (
        <div className="app-shell">
            <Topbar />
            <Sidebar />
            <main className="main-content">{children}</main>
        </div>
    )
}

// ─── App ──────────────────────────────────────────────────────────────────────
export default function App() {
    return (
        <AuthProvider>
            <BrowserRouter>
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="/dashboard" element={<ProtectedLayout><DashboardPage /></ProtectedLayout>} />
                    <Route path="/alerts" element={<ProtectedLayout><AlertsPage /></ProtectedLayout>} />
                    <Route path="/incidents" element={<ProtectedLayout><IncidentsPage /></ProtectedLayout>} />
                    <Route path="/playbooks" element={<ProtectedLayout><PlaybooksPage /></ProtectedLayout>} />
                    <Route path="/rules" element={<ProtectedLayout><RulesPage /></ProtectedLayout>} />
                    <Route path="/settings" element={<ProtectedLayout><SettingsPage /></ProtectedLayout>} />
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                </Routes>
            </BrowserRouter>
        </AuthProvider>
    )
}
