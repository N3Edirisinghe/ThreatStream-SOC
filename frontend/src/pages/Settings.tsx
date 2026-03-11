import { Settings as SettingsIcon, Save, Zap, Terminal, Database, ShieldAlert } from 'lucide-react'
import { useState, useEffect } from 'react'
import { settingsApi, simulationApi } from '../api/client'

// Inline Toast notification component
function Toast({ message, type, onClose }: { message: string, type: 'success' | 'error', onClose: () => void }) {
    useEffect(() => {
        const timer = setTimeout(onClose, 4000)
        return () => clearTimeout(timer)
    }, [onClose])

    return (
        <div style={{
            position: 'fixed', top: '24px', right: '24px',
            background: 'rgba(6, 10, 16, 0.95)',
            border: `1px solid ${type === 'success' ? 'var(--neon-green)' : 'var(--neon-red)'}`,
            padding: '12px 20px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '12px',
            boxShadow: `0 0 20px ${type === 'success' ? 'rgba(0,255,136,0.2)' : 'rgba(255,51,102,0.2)'}`,
            zIndex: 9999,
            animation: 'slideIn 0.3s cubic-bezier(0.23, 1, 0.32, 1) forwards',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem', color: 'var(--text-bright)',
            backdropFilter: 'blur(8px)'
        }}>
            <Zap size={14} color={type === 'success' ? 'var(--neon-green)' : 'var(--neon-red)'} />
            <span>{message.toUpperCase()}</span>
        </div>
    )
}

export default function SettingsPage() {
    const [saved, setSaved] = useState(false)
    const [config, setConfig] = useState({ ml_engine: 'IsolationForest (Enabled)', retention_days: 30 })
    const [loading, setLoading] = useState(true)
    const [saving, setSaving] = useState(false)
    const [simulating, setSimulating] = useState<{ [key: string]: boolean }>({})
    const [toast, setToast] = useState<{ message: string, type: 'success' | 'error' } | null>(null)

    useEffect(() => {
        settingsApi.get()
            .then(res => setConfig(res.data))
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [])

    const handleSave = async () => {
        setSaving(true)
        try {
            await settingsApi.update(config)
            setSaved(true)
            setToast({ message: 'Configuration Synchronized', type: 'success' })
            setTimeout(() => setSaved(false), 2000)
        } finally {
            setSaving(false)
        }
    }

    const runSimulation = async (scenario: string) => {
        setSimulating(prev => ({ ...prev, [scenario]: true }))
        try {
            await simulationApi.trigger(scenario)
            setToast({ message: `INITIATED: ${scenario.toUpperCase()} SIMULATION`, type: 'success' })
        } catch {
            setToast({ message: 'SIMULATION ENGINE ERROR', type: 'error' })
        } finally {
            setSimulating(prev => ({ ...prev, [scenario]: false }))
        }
    }

    return (
        <>
            <div className="page-header">
                <SettingsIcon size={18} color="var(--neon-yellow)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-yellow))' }} />
                <h2 className="page-title">System Config</h2>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 500px) minmax(0, 500px)', gap: 20 }}>
                {/* Platform Config */}
                <div className="card" style={{ height: 'fit-content' }}>
                    <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Database size={14} color="var(--neon-cyan)" /> ENGINE PARAMETERS
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, marginTop: 10 }}>
                        <div>
                            <label style={{ display: 'block', marginBottom: 8, fontSize: '0.65rem', color: 'var(--text-ghost)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                                ML Anomaly Detection
                            </label>
                            <select
                                className="form-input"
                                value={config.ml_engine}
                                onChange={e => setConfig({ ...config, ml_engine: e.target.value })}
                                disabled={loading}
                                style={{ width: '100%', fontSize: '0.8rem' }}
                            >
                                <option value="IsolationForest (Enabled)">IsolationForest (Active)</option>
                                <option value="Disabled">Deactivated</option>
                            </select>
                            <div style={{ fontSize: '0.62rem', color: 'var(--text-ghost)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
                                // Neural engine processing live telemetry for deviations
                            </div>
                        </div>

                        <div>
                            <label style={{ display: 'block', marginBottom: 8, fontSize: '0.65rem', color: 'var(--text-ghost)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                                Log Retention (Horizon)
                            </label>
                            <div style={{ position: 'relative' }}>
                                <input
                                    type="number"
                                    className="form-input"
                                    value={config.retention_days}
                                    onChange={e => setConfig({ ...config, retention_days: parseInt(e.target.value) || 0 })}
                                    disabled={loading}
                                    style={{ width: '100%', fontSize: '0.8rem', paddingRight: 40 }}
                                />
                                <span style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', fontSize: '0.65rem', color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>DAYS</span>
                            </div>
                        </div>

                        <div style={{ marginTop: 10, paddingTop: 20, borderTop: '1px solid var(--border-dim)' }}>
                            <button className="btn btn-ghost" style={{ width: '100%' }} onClick={handleSave} disabled={saved || loading || saving}>
                                {saving ? 'TRANSMITTING...' : saved ? 'SYNCHRONIZED' : <><Save size={14} style={{ marginRight: 8 }} /> COMMIT CHANGES</>}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Attack Emulation */}
                <div className="card" style={{ height: 'fit-content' }}>
                    <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--neon-red)' }}>
                        <ShieldAlert size={14} /> ATTACK EMULATION (PURPLE-TEAM)
                    </div>
                    <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 20, lineHeight: 1.5 }}>
                        Inject synthetic attack signatures into the real-time ingestion pipeline to validate detection capabilities.
                    </p>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                        {[
                            { id: 'ransomware', name: 'Ransomware Chain', tags: 'T1059.001, T1027, T1486' },
                            { id: 'exfiltration', name: 'Data Exfiltration', tags: 'T1039, T1048' }
                        ].map(sim => (
                            <div key={sim.id} style={{
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                padding: '12px 16px', background: 'rgba(0,0,0,0.2)',
                                border: '1px solid var(--border-dim)', borderRadius: 4
                            }}>
                                <div>
                                    <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--text-bright)' }}>{sim.name.toUpperCase()}</div>
                                    <div style={{ fontSize: '0.62rem', color: 'var(--neon-blue)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{sim.tags}</div>
                                </div>
                                <button
                                    className="btn btn-ghost btn-sm"
                                    onClick={() => runSimulation(sim.id)}
                                    disabled={simulating[sim.id]}
                                    style={{ border: '1px solid var(--border-dim)', fontSize: '0.65rem' }}
                                >
                                    {simulating[sim.id] ? 'INJECTING...' : <><Terminal size={12} style={{ marginRight: 6 }} /> EXECUTE</>}
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
        </>
    )
}
