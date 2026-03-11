import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Lock, User, Terminal, Activity } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'

// Animated text lines to simulate terminal boot
const BOOT_LINES = [
    '> INITIALIZING SECURE ENCLAVE...',
    '> LOADING THREAT INTELLIGENCE DATABASE...',
    '> CONNECTING TO KAFKA STREAM...',
    '> AUTHENTICATION MODULE ONLINE.',
]

export default function Login() {
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [loading, setLoading] = useState(false)
    const { login } = useAuth()
    const navigate = useNavigate()

    async function handleSubmit(e: React.FormEvent) {
        e.preventDefault()
        setError(''); setLoading(true)
        try {
            await login(username, password)
            navigate('/dashboard')
        } catch (err: any) {
            setError(err.response?.data?.detail || 'ACCESS DENIED. Check credentials.')
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="login-page">
            {/* Grid lines bg effect already done via CSS */}
            <div style={{ width: '100%', maxWidth: 480, padding: 24 }}>

                {/* Boot sequence panel */}
                <div style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.7rem',
                    color: 'var(--text-muted)',
                    marginBottom: 24,
                    padding: '12px 16px',
                    background: 'rgba(0,0,0,0.5)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 4,
                    lineHeight: 2,
                }}>
                    {BOOT_LINES.map((line, i) => (
                        <div key={i} style={{ animation: `fadeIn 0.5s ease ${i * 0.3}s both` }}>
                            <span style={{ color: 'var(--neon-green)' }}>$ </span>
                            {line}
                        </div>
                    ))}
                </div>

                <div className="login-card">
                    <div className="login-logo">
                        <Shield
                            size={44}
                            color="var(--neon-green)"
                            style={{ filter: 'drop-shadow(0 0 16px rgba(0,255,136,0.5))' }}
                        />
                        <h1>SOC Platform</h1>
                        <p>AUTONOMOUS SECURITY OPERATIONS CENTER</p>
                    </div>

                    <form onSubmit={handleSubmit}>
                        <div className="form-group">
                            <label className="form-label">
                                <User size={11} /> Operator ID
                            </label>
                            <input
                                className="form-input"
                                type="text"
                                value={username}
                                onChange={e => setUsername(e.target.value)}
                                placeholder="admin"
                                autoFocus
                                required
                            />
                        </div>

                        <div className="form-group">
                            <label className="form-label">
                                <Lock size={11} /> Auth Token
                            </label>
                            <input
                                className="form-input"
                                type="password"
                                value={password}
                                onChange={e => setPassword(e.target.value)}
                                placeholder="••••••••••••"
                                required
                            />
                        </div>

                        {error && <div className="error-msg">⚠ {error}</div>}

                        <button
                            type="submit"
                            className="btn btn-primary"
                            style={{ width: '100%', marginTop: 24, justifyContent: 'center', padding: '12px', fontSize: '0.82rem' }}
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <Activity size={14} className="pulse" />
                                    AUTHENTICATING...
                                </>
                            ) : (
                                <>
                                    <Terminal size={14} />
                                    ESTABLISH SECURE SESSION
                                </>
                            )}
                        </button>
                    </form>

                    <p style={{
                        textAlign: 'center', marginTop: 20,
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.68rem', color: 'var(--text-ghost)',
                        letterSpacing: '0.5px',
                    }}>
                        DEFAULT: admin / Admin@SOC123!
                    </p>
                </div>

                <p style={{ textAlign: 'center', marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-ghost)', letterSpacing: 1 }}>
                    ENCRYPTED CONNECTION ● AES-256 ● ZERO-TRUST ARCHITECTURE
                </p>
            </div>

            <style>{`
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(4px); }
                    to { opacity: 1; transform: none; }
                }
            `}</style>
        </div>
    )
}
