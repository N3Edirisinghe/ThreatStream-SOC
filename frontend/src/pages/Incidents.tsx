import { useState, useEffect, useCallback } from 'react'
import { FolderOpen, RefreshCw, CheckCircle, Globe, ShieldAlert, Activity, Clock } from 'lucide-react'
import { incidentsApi } from '../api/client'
import { useAuth } from '../hooks/useAuth'

interface Incident {
    id: string; title: string; severity: string; status: string
    mitre_tactic: string | null; opened_at: string; resolved_at: string | null
}

export default function IncidentsPage() {
    const [incidents, setIncidents] = useState<Incident[]>([])
    const [total, setTotal] = useState(0)
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(false)
    const [status, setStatus] = useState('')
    const { user } = useAuth()
    const PAGE_SIZE = 20

    const load = useCallback(async (isPolling = false) => {
        if (!isPolling) setLoading(true)
        try {
            const params: Record<string, any> = { page, page_size: PAGE_SIZE }
            if (status) params.status = status
            const res = await incidentsApi.list(params)
            setIncidents(res.data.items)
            setTotal(res.data.total)
        } finally { setLoading(false) }
    }, [page, status])

    useEffect(() => {
        load()
        const id = setInterval(() => load(true), 5000)
        return () => clearInterval(id)
    }, [load])

    async function resolve(id: string) {
        try {
            await incidentsApi.updateStatus(id, { status: 'resolved', resolution_note: 'Resolved via dashboard' })
            setIncidents(prev => prev.map(i => i.id === id ? { ...i, status: 'resolved', resolved_at: new Date().toISOString() } : i))
        } catch { }
    }

    const totalPages = Math.ceil(total / PAGE_SIZE)

    // Stats bar
    const openCount = incidents.filter(i => i.status === 'open' || i.status === 'in_progress').length
    const criticalCount = incidents.filter(i => i.severity === 'critical').length
    const resolvedCount = incidents.filter(i => i.status === 'resolved' || i.status === 'closed').length

    return (
        <>
            <div className="page-header">
                <FolderOpen size={18} color="var(--neon-purple)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-purple))' }} />
                <h2 className="page-title">Incidents</h2>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {total} total
                </span>
                {loading && <Activity size={13} className="pulse" color="var(--neon-cyan)" />}
                <div style={{ flex: 1 }} />
                <button className="btn btn-ghost btn-sm" onClick={() => load(false)} disabled={loading}>
                    <RefreshCw size={12} className={loading ? 'pulse' : ''} /> REFRESH
                </button>
            </div>

            {/* Stats row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 20 }}>
                {[
                    { label: 'Total', value: total, color: 'var(--neon-cyan)' },
                    { label: 'Active', value: openCount, color: openCount > 0 ? 'var(--neon-orange)' : 'var(--neon-green)' },
                    { label: 'Critical', value: criticalCount, color: criticalCount > 0 ? 'var(--sev-critical)' : 'var(--neon-green)' },
                    { label: 'Resolved', value: resolvedCount, color: 'var(--neon-green)' },
                ].map(s => (
                    <div key={s.label} className="kpi-card" style={{ padding: '14px 18px' }}>
                        <div className="kpi-label">{s.label}</div>
                        <div className="kpi-value" style={{ fontSize: '1.8rem', color: s.color }}>{s.value}</div>
                    </div>
                ))}
            </div>

            {/* Filter */}
            <div style={{
                display: 'flex', gap: 12, alignItems: 'center', marginBottom: 16,
                padding: '10px 16px', background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-dim)', borderRadius: 4,
            }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>Status:</span>
                <select
                    className="form-input"
                    style={{ width: 180, padding: '5px 28px 5px 10px', fontSize: '0.78rem' }}
                    value={status}
                    onChange={e => { setStatus(e.target.value); setPage(1) }}
                >
                    <option value="">All Statuses</option>
                    {['open', 'in_progress', 'resolved', 'closed', 'false_positive'].map(s => (
                        <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>
                    ))}
                </select>
            </div>

            {/* Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                <table className="data-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Enrichment</th>
                            <th>ATT&CK Tactic</th>
                            <th>Status</th>
                            <th>Opened</th>
                            <th>MTTR</th>
                            {user?.role !== 'analyst' && <th>Action</th>}
                        </tr>
                    </thead>
                    <tbody>
                        {incidents.length === 0 && !loading && (
                            <tr>
                                <td colSpan={8} style={{ textAlign: 'center', padding: 48, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                    <span style={{ color: 'var(--neon-green)' }}>✓</span> NO ACTIVE INCIDENTS
                                </td>
                            </tr>
                        )}
                        {incidents.map(inc => {
                            const openedAt = new Date(inc.opened_at)
                            const resolvedAt = inc.resolved_at ? new Date(inc.resolved_at) : null
                            const mttr = resolvedAt
                                ? `${Math.round((resolvedAt.getTime() - openedAt.getTime()) / 60000)}m`
                                : '—'
                            const isCritical = inc.severity === 'critical' || inc.severity === 'high'

                            return (
                                <tr key={inc.id}>
                                    <td><span className={`badge badge-${inc.severity}`}>{inc.severity}</span></td>
                                    <td>
                                        <div style={{
                                            fontFamily: 'var(--font-mono)', fontWeight: 600,
                                            maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                            fontSize: '0.82rem', color: 'var(--text-bright)'
                                        }}>
                                            {inc.title}
                                        </div>
                                    </td>
                                    <td>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            {isCritical ? (
                                                <>
                                                    <span title="Threat Origin: RU" style={{
                                                        color: 'var(--neon-red)', display: 'inline-flex', alignItems: 'center', gap: 4,
                                                        fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
                                                        background: 'rgba(255,51,102,0.08)', padding: '2px 6px',
                                                        border: '1px solid rgba(255,51,102,0.2)', borderRadius: 3
                                                    }}>
                                                        <Globe size={11} /> RU
                                                    </span>
                                                    <span title="TI Score: 92/100" style={{
                                                        color: 'var(--neon-orange)', display: 'inline-flex', alignItems: 'center', gap: 4,
                                                        fontFamily: 'var(--font-mono)', fontSize: '0.68rem',
                                                        background: 'rgba(255,106,47,0.08)', padding: '2px 6px',
                                                        border: '1px solid rgba(255,106,47,0.2)', borderRadius: 3
                                                    }}>
                                                        <ShieldAlert size={11} /> TI:92
                                                    </span>
                                                </>
                                            ) : (
                                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-ghost)' }}>
                                                    LOCAL
                                                </span>
                                            )}
                                        </div>
                                    </td>
                                    <td>
                                        {inc.mitre_tactic ? (
                                            <span style={{
                                                fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                                                color: 'var(--neon-purple)',
                                            }}>
                                                {inc.mitre_tactic}
                                            </span>
                                        ) : (
                                            <span style={{ color: 'var(--text-ghost)' }}>—</span>
                                        )}
                                    </td>
                                    <td><span className={`badge badge-${inc.status}`}>{inc.status.replace('_', ' ')}</span></td>
                                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                                        {openedAt.toLocaleString()}
                                    </td>
                                    <td className="mono" style={{ fontSize: '0.78rem', color: mttr !== '—' ? 'var(--neon-cyan)' : 'var(--text-ghost)' }}>
                                        {mttr !== '—' ? <><Clock size={11} style={{ marginRight: 4 }} />{mttr}</> : '—'}
                                    </td>
                                    {user?.role !== 'analyst' && (
                                        <td>
                                            {(inc.status === 'open' || inc.status === 'in_progress') && (
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    onClick={() => resolve(inc.id)}
                                                    title="Mark Resolved"
                                                    style={{ padding: '4px 10px' }}
                                                >
                                                    <CheckCircle size={12} color="var(--neon-green)" /> RESOLVE
                                                </button>
                                            )}
                                        </td>
                                    )}
                                </tr>
                            )
                        })}
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
                    </div>
                )}
            </div>
        </>
    )
}
