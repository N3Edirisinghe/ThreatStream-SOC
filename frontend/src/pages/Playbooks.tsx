import { useState, useEffect } from 'react'
import { PlayCircle, Cpu, CheckCircle, XCircle, Zap, Shield, Activity, Lock, Unlock } from 'lucide-react'
import { playbooksApi } from '../api/client'

interface Playbook {
    id: string; name: string; trigger: string;
    action: string; enabled: boolean;
}

function Toast({ message, type, onClose }: { message: string, type: 'success' | 'error', onClose: () => void }) {
    useEffect(() => {
        const timer = setTimeout(onClose, 3500)
        return () => clearTimeout(timer)
    }, [onClose])

    return (
        <div style={{
            position: 'fixed', bottom: '28px', right: '28px',
            background: 'rgba(6,10,16,0.98)',
            border: `1px solid ${type === 'success' ? 'var(--neon-green)' : 'var(--neon-red)'}`,
            padding: '14px 18px', borderRadius: 4,
            display: 'flex', alignItems: 'center', gap: '12px',
            boxShadow: `0 0 24px ${type === 'success' ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)'}`,
            zIndex: 99999, animation: 'slideIn 0.3s ease-out forwards',
            fontFamily: 'var(--font-mono)',
        }}>
            {type === 'success'
                ? <CheckCircle size={16} color="var(--neon-green)" />
                : <XCircle size={16} color="var(--neon-red)" />}
            <span style={{ fontSize: '0.82rem', color: 'var(--text-bright)' }}>{message}</span>
        </div>
    )
}

const TACTIC_ICONS: Record<string, React.ReactNode> = {
    'Credential Access': <Lock size={14} />,
    'Lateral Movement': <Zap size={14} />,
    'Defense Evasion': <Shield size={14} />,
    'Exfiltration': <Activity size={14} />,
}

export default function PlaybooksPage() {
    const [playbooks, setPlaybooks] = useState<Playbook[]>([])
    const [loading, setLoading] = useState(true)
    const [runningId, setRunningId] = useState<string | null>(null)
    const [toast, setToast] = useState<{ message: string, type: 'success' | 'error' } | null>(null)

    useEffect(() => {
        playbooksApi.list()
            .then(res => setPlaybooks(res.data))
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [])

    const handleRun = async (id: string, name: string) => {
        setRunningId(id)
        try {
            await playbooksApi.execute(id)
            await new Promise(r => setTimeout(r, 1000))
            setToast({ message: `[EXECUTED] ${name}`, type: 'success' })
        } catch {
            setToast({ message: `[FAILED] ${name}`, type: 'error' })
        } finally {
            setRunningId(null)
        }
    }

    return (
        <>
            <div className="page-header">
                <Cpu size={18} color="var(--neon-blue)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-blue))' }} />
                <h2 className="page-title">SOAR Engine</h2>
                <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                    color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6
                }}>
                    {playbooks.filter(p => p.enabled).length} AUTO-ACTIVE
                </span>
            </div>

            {/* Summary stats row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
                {[
                    { label: 'Total Playbooks', value: playbooks.length, color: 'var(--neon-cyan)' },
                    { label: 'Auto-Active', value: playbooks.filter(p => p.enabled).length, color: 'var(--neon-green)' },
                    { label: 'Manual Only', value: playbooks.filter(p => !p.enabled).length, color: 'var(--text-muted)' },
                ].map(s => (
                    <div key={s.label} className="kpi-card" style={{ padding: '16px 20px' }}>
                        <div className="kpi-label">{s.label}</div>
                        <div className="kpi-value" style={{ fontSize: '1.8rem', color: s.color }}>{s.value}</div>
                    </div>
                ))}
            </div>

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                {loading && (
                    <div className="loading" style={{ height: 80 }}>
                        <Activity size={14} className="pulse" color="var(--neon-cyan)" />
                        LOADING PLAYBOOK LIBRARY...
                    </div>
                )}

                {!loading && playbooks.length === 0 && (
                    <div style={{ padding: 40, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                        NO PLAYBOOKS CONFIGURED
                    </div>
                )}

                {!loading && playbooks.length > 0 && (
                    <div style={{ display: 'grid', gap: 0 }}>
                        {/* Header */}
                        <div style={{
                            display: 'grid', gridTemplateColumns: '120px 1fr 1fr 160px 140px',
                            padding: '10px 20px', borderBottom: '1px solid var(--border-mid)',
                            fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted)',
                            textTransform: 'uppercase', letterSpacing: '1.5px', gap: 16
                        }}>
                            <span>Status</span>
                            <span>Playbook</span>
                            <span>Trigger</span>
                            <span>Action</span>
                            <span>Execute</span>
                        </div>

                        {playbooks.map((pb, index) => (
                            <div key={pb.id} style={{
                                display: 'grid', gridTemplateColumns: '120px 1fr 1fr 160px 140px',
                                padding: '16px 20px', gap: 16, alignItems: 'center',
                                borderBottom: index < playbooks.length - 1 ? '1px solid var(--border-dim)' : 'none',
                                transition: 'background 0.15s',
                                cursor: 'default',
                            }}
                                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,229,255,0.02)')}
                                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                            >
                                {/* Status */}
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                    {pb.enabled ? (
                                        <>
                                            <span style={{
                                                display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
                                                background: 'var(--neon-green)',
                                                boxShadow: '0 0 6px var(--neon-green)',
                                                animation: 'pulse 2s infinite'
                                            }} />
                                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--neon-green)', letterSpacing: 1 }}>AUTO</span>
                                        </>
                                    ) : (
                                        <>
                                            <span style={{
                                                display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
                                                background: 'var(--text-muted)',
                                            }} />
                                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: 1 }}>MANUAL</span>
                                        </>
                                    )}
                                </div>

                                {/* Name */}
                                <div>
                                    <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-bright)' }}>
                                        {pb.name}
                                    </div>
                                </div>

                                {/* Trigger */}
                                <div>
                                    <span style={{
                                        fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
                                        color: 'var(--neon-orange)', background: 'rgba(255,106,47,0.08)',
                                        border: '1px solid rgba(255,106,47,0.2)', borderRadius: 3,
                                        padding: '3px 8px', display: 'inline-block'
                                    }}>
                                        {pb.trigger}
                                    </span>
                                </div>

                                {/* Action */}
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                    {pb.action}
                                </div>

                                {/* Execute button */}
                                <div>
                                    <button
                                        className="btn btn-outline btn-sm"
                                        onClick={() => handleRun(pb.id, pb.name)}
                                        disabled={runningId === pb.id}
                                        style={{ width: '100%', justifyContent: 'center' }}
                                    >
                                        {runningId === pb.id ? (
                                            <><Activity size={12} className="pulse" /> RUNNING...</>
                                        ) : (
                                            <><PlayCircle size={12} /> FORCE RUN</>
                                        )}
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

            <style>{`
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `}</style>
        </>
    )
}
