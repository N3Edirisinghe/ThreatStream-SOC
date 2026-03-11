import { useState, useEffect, useCallback } from 'react'
import { Siren, CheckCircle, XCircle, RefreshCw, Activity, Filter } from 'lucide-react'
import { alertsApi } from '../api/client'

interface Alert {
    id: string; rule_name: string; severity: string; detection_type: string
    status: string; host_name: string; user_name: string; source_ip: string
    mitre_tactic: string; mitre_technique: string; triggered_at: string; incident_id: string | null
}

function SeverityBadge({ sev }: { sev: string }) {
    return <span className={`badge badge-${sev}`}>{sev}</span>
}
function StatusBadge({ st }: { st: string }) {
    return <span className={`badge badge-${st}`}>{st.replace(/_/g, ' ')}</span>
}

export default function AlertsPage() {
    const [alerts, setAlerts] = useState<Alert[]>([])
    const [total, setTotal] = useState(0)
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(false)
    const [severity, setSeverity] = useState('')
    const [status, setStatus] = useState('')
    const [actioning, setActioning] = useState<string | null>(null)
    const PAGE_SIZE = 20

    const load = useCallback(async (isPolling = false) => {
        if (!isPolling) setLoading(true)
        try {
            const params: Record<string, any> = { page, page_size: PAGE_SIZE }
            if (severity) params.severity = severity
            if (status) params.status = status
            const res = await alertsApi.list(params)
            setAlerts(res.data.items)
            setTotal(res.data.total)
        } catch (err) {
            console.error("Failed to load alerts:", err)
        }
        finally { setLoading(false) }
    }, [page, severity, status])

    useEffect(() => { load() }, [load])
    useEffect(() => {
        const id = setInterval(() => load(true), 5000)
        return () => clearInterval(id)
    }, [load])

    async function acknowledge(id: string) {
        setActioning(id)
        try {
            await alertsApi.acknowledge(id)
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'acknowledged' } : a))
        } finally { setActioning(null) }
    }

    async function markFP(id: string) {
        setActioning(id)
        try {
            await alertsApi.falsePositive(id)
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: 'false_positive' } : a))
        } finally { setActioning(null) }
    }

    const totalPages = Math.ceil(total / PAGE_SIZE)

    return (
        <>
            {/* Header */}
            <div className="page-header">
                <Siren size={18} color="var(--neon-yellow)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-yellow))' }} />
                <h2 className="page-title">Alert Queue</h2>
                <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                    color: 'var(--text-muted)'
                }}>
                    {total.toLocaleString()} events
                </span>
                {loading && <Activity size={13} className="pulse" color="var(--neon-cyan)" />}
                <div style={{ flex: 1 }} />
                <button className="btn btn-ghost btn-sm" onClick={() => load(false)} disabled={loading}>
                    <RefreshCw size={12} className={loading ? 'pulse' : ''} /> REFRESH
                </button>
            </div>

            {/* Filter Bar */}
            <div style={{
                display: 'flex', gap: 12, alignItems: 'center', marginBottom: 16,
                padding: '12px 16px',
                background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-dim)',
                borderRadius: 4, fontFamily: 'var(--font-mono)',
            }}>
                <Filter size={13} color="var(--text-muted)" />
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>Filter:</span>
                <select
                    className="form-input"
                    style={{ width: 150, padding: '5px 28px 5px 10px', fontSize: '0.78rem' }}
                    value={severity}
                    onChange={e => { setSeverity(e.target.value); setPage(1) }}
                >
                    <option value="">All Severities</option>
                    {['critical', 'high', 'medium', 'low', 'informational'].map(s => (
                        <option key={s} value={s}>{s.toUpperCase()}</option>
                    ))}
                </select>
                <select
                    className="form-input"
                    style={{ width: 160, padding: '5px 28px 5px 10px', fontSize: '0.78rem' }}
                    value={status}
                    onChange={e => { setStatus(e.target.value); setPage(1) }}
                >
                    <option value="">All Statuses</option>
                    {['open', 'acknowledged', 'false_positive', 'resolved'].map(s => (
                        <option key={s} value={s}>{s.replace('_', ' ').toUpperCase()}</option>
                    ))}
                </select>
                {(severity || status) && (
                    <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => { setSeverity(''); setStatus(''); setPage(1) }}
                    >
                        CLEAR
                    </button>
                )}
                <div style={{ flex: 1 }} />
                <span style={{ fontSize: '0.68rem', color: 'var(--text-ghost)' }}>
                    AUTO-REFRESH: 5s
                </span>
            </div>

            {/* Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Rule / Detection</th>
                            <th>Host</th>
                            <th>User</th>
                            <th>Source IP</th>
                            <th>ATT&CK</th>
                            <th>Timestamp</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alerts.length === 0 && !loading && (
                            <tr>
                                <td colSpan={9} style={{ textAlign: 'center', padding: 48, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                    <span style={{ color: 'var(--neon-green)' }}>✓</span> NO ALERTS — THREAT QUEUE EMPTY
                                </td>
                            </tr>
                        )}
                        {alerts.map(alert => (
                            <tr key={alert.id}>
                                <td><SeverityBadge sev={alert.severity} /></td>
                                <td>
                                    <div style={{
                                        fontFamily: 'var(--font-mono)', fontWeight: 600,
                                        maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                        fontSize: '0.8rem', color: 'var(--text-bright)'
                                    }}>
                                        {alert.rule_name}
                                    </div>
                                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>
                                        {alert.detection_type}
                                    </div>
                                </td>
                                <td className="mono">{alert.host_name || '—'}</td>
                                <td className="mono">{alert.user_name || '—'}</td>
                                <td className="mono" style={{ color: alert.source_ip ? 'var(--neon-orange)' : undefined }}>
                                    {alert.source_ip || '—'}
                                </td>
                                <td>
                                    {alert.mitre_tactic && (
                                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--neon-purple)' }}>
                                            {alert.mitre_tactic}
                                        </div>
                                    )}
                                    {alert.mitre_technique && (
                                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--neon-blue)', marginTop: 2 }}>
                                            {alert.mitre_technique}
                                        </div>
                                    )}
                                </td>
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                                    {new Date(alert.triggered_at).toLocaleString()}
                                </td>
                                <td><StatusBadge st={alert.status} /></td>
                                <td>
                                    <div style={{ display: 'flex', gap: 4 }}>
                                        {alert.status === 'open' && (
                                            <>
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    title="Acknowledge"
                                                    disabled={actioning === alert.id}
                                                    onClick={() => acknowledge(alert.id)}
                                                    style={{ padding: '4px 8px' }}
                                                >
                                                    <CheckCircle size={12} color="var(--neon-green)" />
                                                </button>
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    title="Mark False Positive"
                                                    disabled={actioning === alert.id}
                                                    onClick={() => markFP(alert.id)}
                                                    style={{ padding: '4px 8px' }}
                                                >
                                                    <XCircle size={12} color="var(--text-muted)" />
                                                </button>
                                            </>
                                        )}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {totalPages > 1 && (
                    <div style={{
                        display: 'flex', alignItems: 'center', gap: 12, padding: '12px 20px',
                        borderTop: '1px solid var(--border-dim)',
                        fontFamily: 'var(--font-mono)', fontSize: '0.72rem'
                    }}>
                        <button className="btn btn-ghost btn-sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← PREV</button>
                        <span style={{ color: 'var(--text-muted)' }}>PAGE {page} / {totalPages}</span>
                        <button className="btn btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>NEXT →</button>
                        <div style={{ flex: 1 }} />
                        <span style={{ color: 'var(--text-ghost)' }}>{total.toLocaleString()} TOTAL EVENTS</span>
                    </div>
                )}
            </div>
        </>
    )
}
