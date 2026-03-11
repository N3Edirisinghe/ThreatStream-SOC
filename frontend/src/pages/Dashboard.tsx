import { useState, useEffect, useRef } from 'react'
import { Activity, TrendingUp, AlertTriangle, ShieldAlert, Clock, Target, Radio, Zap } from 'lucide-react'
import { metricsApi, alertsApi } from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, AreaChart, Area } from 'recharts'
import { useLiveFeed, useAnimatedNumber } from '../hooks/useLiveFeed'

interface KPI {
    period: string; total_alerts: number; open_incidents: number; critical_incidents: number
    false_positive_rate: number; true_positive_rate: number; mttr_minutes: number | null
}

// ─── Animated KPI Card ────────────────────────────────────────────────────────
function KpiCard({ label, rawValue, suffix = '', sub, color, icon, warning }: {
    label: string
    rawValue: number
    suffix?: string
    sub?: string
    color?: string
    icon?: React.ReactNode
    warning?: boolean
}) {
    const animated = useAnimatedNumber(rawValue)
    return (
        <div className="kpi-card" style={{ borderLeftColor: color || 'var(--neon-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div className="kpi-label">{label}</div>
                {icon && <div style={{ color: color || 'var(--neon-cyan)', opacity: 0.7 }}>{icon}</div>}
            </div>
            <div className="kpi-value" style={{ color: color || 'var(--neon-cyan)' }}>
                {animated}{suffix}
            </div>
            {sub && <div className="kpi-sub">{sub}</div>}
            {warning && animated > 0 && (
                <div style={{
                    position: 'absolute', top: 8, right: 8,
                    width: 7, height: 7, borderRadius: '50%',
                    background: color || 'var(--sev-critical)',
                    boxShadow: `0 0 8px ${color || 'var(--sev-critical)'}`,
                    animation: 'pulse 1.5s infinite'
                }} />
            )}
        </div>
    )
}

// ─── Severity colour map ───────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
    informational: 'var(--sev-info)',
}

// ─── Live Threat Feed ─────────────────────────────────────────────────────────
function LiveThreatFeed() {
    const { feed, newCount, clearNewCount } = useLiveFeed(30)
    const feedRef = useRef<HTMLDivElement>(null)

    useEffect(() => {
        if (feedRef.current) feedRef.current.scrollTop = 0
        if (newCount > 0) clearNewCount()
    }, [feed.length])

    return (
        <div className="card" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Feed header */}
            <div style={{
                padding: '12px 16px',
                borderBottom: '1px solid var(--border-dim)',
                display: 'flex', alignItems: 'center', gap: 10,
                background: 'rgba(0,0,0,0.3)'
            }}>
                <Radio size={13} color="var(--neon-red)" style={{ animation: 'pulse 1.5s infinite' }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 2 }}>
                    Live Threat Feed
                </span>
                {newCount > 0 && (
                    <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                        background: 'rgba(255,51,102,0.2)', color: 'var(--neon-red)',
                        border: '1px solid rgba(255,51,102,0.4)',
                        padding: '1px 7px', borderRadius: 2
                    }}>
                        +{newCount} NEW
                    </span>
                )}
                <div style={{ flex: 1 }} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-ghost)' }}>
                    <span className="live-dot" />polling 3s
                </span>
            </div>

            {/* Scrollable feed */}
            <div
                ref={feedRef}
                style={{ overflowY: 'auto', maxHeight: 380, flex: 1 }}
            >
                {feed.length === 0 ? (
                    <div style={{
                        padding: 32, textAlign: 'center', fontFamily: 'var(--font-mono)',
                        fontSize: '0.78rem', color: 'var(--text-muted)'
                    }}>
                        <span style={{ color: 'var(--neon-green)' }}>✓</span> NO ACTIVE THREATS
                    </div>
                ) : (
                    feed.map((alert, i) => (
                        <div
                            key={alert.id}
                            style={{
                                display: 'grid',
                                gridTemplateColumns: '80px 1fr 100px 110px',
                                gap: 10,
                                padding: '8px 16px',
                                borderBottom: '1px solid var(--border-dim)',
                                alignItems: 'center',
                                background: alert.isNew ? 'rgba(0,229,255,0.06)' : 'transparent',
                                borderLeft: alert.isNew ? '2px solid var(--neon-cyan)' : '2px solid transparent',
                                transition: 'background 1s ease, border-left 1s ease',
                                animation: alert.isNew ? 'slideDown 0.4s ease' : undefined,
                            }}
                        >
                            {/* Severity */}
                            <span className={`badge badge-${alert.severity}`} style={{ fontSize: '0.62rem' }}>
                                {alert.severity}
                            </span>

                            {/* Rule name */}
                            <div>
                                <div style={{
                                    fontFamily: 'var(--font-mono)', fontSize: '0.76rem',
                                    color: 'var(--text-bright)',
                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200
                                }}>
                                    {alert.rule_name}
                                </div>
                                {alert.mitre_tactic && (
                                    <div style={{ fontSize: '0.65rem', color: 'var(--neon-purple)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
                                        {alert.mitre_tactic}
                                    </div>
                                )}
                            </div>

                            {/* Host */}
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {alert.host_name || '—'}
                            </div>

                            {/* Time */}
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-ghost)', textAlign: 'right' }}>
                                {new Date(alert.triggered_at).toLocaleTimeString()}
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    )
}

// ─── Mini Sparkline ─────────────────────────────────────────────────────────
function ActivitySparkline({ data }: { data: any[] }) {
    if (!data.length) return null
    return (
        <ResponsiveContainer width="100%" height={70}>
            <AreaChart data={data} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
                <defs>
                    <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#b04dff" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#b04dff" stopOpacity={0} />
                    </linearGradient>
                </defs>
                <Area
                    type="monotone"
                    dataKey="total"
                    stroke="#b04dff"
                    strokeWidth={2}
                    fill="url(#areaGrad)"
                    dot={false}
                    isAnimationActive={true}
                />
            </AreaChart>
        </ResponsiveContainer>
    )
}

// ─── Custom Tooltip  ─────────────────────────────────────────────────────────
const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload?.length) {
        return (
            <div style={{
                background: 'rgba(6,10,16,0.96)', border: '1px solid var(--border-mid)',
                borderRadius: 4, padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '0.72rem'
            }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
                {payload.map((p: any, i: number) => (
                    <div key={i} style={{ color: p.fill, display: 'flex', justifyContent: 'space-between', gap: 20 }}>
                        <span>{p.name}</span><span style={{ fontWeight: 700 }}>{p.value}</span>
                    </div>
                ))}
            </div>
        )
    }
    return null
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function DashboardPage() {
    const [kpi, setKpi] = useState<KPI | null>(null)
    const [volume, setVolume] = useState<any[]>([])
    const [heatmap, setHeatmap] = useState<any[]>([])
    const [loading, setLoading] = useState(true)
    const [tick, setTick] = useState(0)  // force time re-render
    const [pulseKey, setPulseKey] = useState(0)

    useEffect(() => {
        const load = () => {
            Promise.all([
                metricsApi.kpi(7),
                metricsApi.alertVolume(7),
                metricsApi.attackHeatmap(7),
            ]).then(([k, v, h]) => {
                setKpi(prev => {
                    if (JSON.stringify(prev) !== JSON.stringify(k.data)) setPulseKey(x => x + 1)
                    return k.data
                })
                setVolume(v.data.data || [])
                setHeatmap(h.data || [])
            }).catch(() => { }).finally(() => setLoading(false))
        }
        load()
        const id = setInterval(load, 5000)
        return () => clearInterval(id)
    }, [])

    // Clock tick
    useEffect(() => {
        const id = setInterval(() => setTick(t => t + 1), 1000)
        return () => clearInterval(id)
    }, [])

    if (loading) return (
        <div className="loading">
            <Activity size={16} className="pulse" color="var(--neon-cyan)" />
            LOADING THREAT INTELLIGENCE...
        </div>
    )

    return (
        <>
            {/* Header */}
            <div className="page-header">
                <Activity size={18} color="var(--neon-cyan)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-cyan))' }} />
                <h2 className="page-title">Threat Dashboard</h2>
                <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
                    background: 'rgba(0,255,136,0.08)', color: 'var(--neon-green)',
                    padding: '4px 10px', borderRadius: 3,
                    border: '1px solid rgba(0,255,136,0.2)',
                    display: 'flex', alignItems: 'center', gap: 6
                }}>
                    <span className="live-dot" />LIVE — LAST 7 DAYS
                </span>
                <div style={{ flex: 1 }} />
                <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--neon-cyan)',
                    background: 'rgba(0,229,255,0.06)', padding: '4px 10px',
                    border: '1px solid var(--border-mid)', borderRadius: 3
                }}>
                    {new Date().toLocaleString()}
                </span>
            </div>

            {/* KPI Cards */}
            {kpi && (
                <div className="kpi-grid" key={pulseKey}>
                    <KpiCard
                        label="Total Alerts"
                        rawValue={kpi.total_alerts}
                        sub="7-day window"
                        icon={<AlertTriangle size={16} />}
                        color="var(--neon-cyan)"
                    />
                    <KpiCard
                        label="Open Incidents"
                        rawValue={kpi.open_incidents}
                        color={kpi.open_incidents > 0 ? 'var(--sev-high)' : 'var(--neon-green)'}
                        warning={kpi.open_incidents > 0}
                        icon={<ShieldAlert size={16} />}
                    />
                    <KpiCard
                        label="Critical Open"
                        rawValue={kpi.critical_incidents}
                        color={kpi.critical_incidents > 0 ? 'var(--sev-critical)' : 'var(--neon-green)'}
                        sub={kpi.critical_incidents > 0 ? '⚠ Immediate action needed' : 'All clear'}
                        warning={kpi.critical_incidents > 0}
                        icon={<Target size={16} />}
                    />
                    <KpiCard
                        label="MTTR"
                        rawValue={kpi.mttr_minutes ?? 0}
                        suffix={kpi.mttr_minutes ? 'm' : ''}
                        sub={kpi.mttr_minutes ? 'Mean time to resolve' : 'No resolved incidents'}
                        icon={<Clock size={16} />}
                        color="var(--neon-blue)"
                    />
                    <KpiCard
                        label="True Positive Rate"
                        rawValue={Math.round(kpi.true_positive_rate * 100)}
                        suffix="%"
                        color={kpi.true_positive_rate >= 0.8 ? 'var(--neon-green)' : 'var(--neon-yellow)'}
                        icon={<TrendingUp size={16} />}
                    />
                    <KpiCard
                        label="False Positive Rate"
                        rawValue={Math.round(kpi.false_positive_rate * 100)}
                        suffix="%"
                        sub={kpi.false_positive_rate < 0.1 ? 'Excellent accuracy' : 'Review rules'}
                        color={kpi.false_positive_rate < 0.1 ? 'var(--neon-green)' : 'var(--sev-high)'}
                        icon={<Activity size={16} />}
                    />
                </div>
            )}

            {/* Charts row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
                {/* Alert Volume */}
                {volume.length > 0 && (
                    <div className="card" style={{ paddingBottom: 12 }}>
                        <div className="card-title">Alert Volume · 7 days</div>
                        {/* Sparkline summary */}
                        <ActivitySparkline data={volume} />
                        <ResponsiveContainer width="100%" height={170}>
                            <BarChart data={volume} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,0.03)" vertical={false} />
                                <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} />
                                <YAxis tick={{ fontSize: 9, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} />
                                <Bar dataKey="critical" name="Critical" stackId="a" fill="#ff1744" isAnimationActive={true} animationDuration={800} />
                                <Bar dataKey="high" name="High" stackId="a" fill="#b04dff" isAnimationActive={true} animationDuration={800} />
                                <Bar dataKey="medium" name="Medium" stackId="a" fill="#2979ff" isAnimationActive={true} animationDuration={800} />
                                <Bar dataKey="low" name="Low" stackId="a" fill="#00e5ff" radius={[2, 2, 0, 0]} isAnimationActive={true} animationDuration={800} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                )}

                {/* MITRE Heatmap */}
                {heatmap.length > 0 && (
                    <div className="card">
                        <div className="card-title">MITRE ATT&CK Tactics</div>
                        <ResponsiveContainer width="100%" height={240}>
                            <BarChart layout="vertical" data={heatmap} margin={{ top: 8, right: 20, left: 60, bottom: 0 }}>
                                <XAxis type="number" hide />
                                <YAxis dataKey="tactic" type="category" tick={{ fontSize: 10, fill: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }} axisLine={false} tickLine={false} />
                                <Tooltip content={<CustomTooltip />} />
                                <Bar dataKey="count" name="Alerts" radius={[0, 3, 3, 0]} barSize={14} isAnimationActive={true} animationDuration={800}>
                                    {heatmap.map((entry, index) => (
                                        <Cell key={index} fill={
                                            entry.count > 20 ? 'var(--sev-critical)'
                                                : entry.count > 10 ? 'var(--sev-high)'
                                                    : entry.count > 4 ? 'var(--sev-medium)'
                                                        : 'var(--neon-blue)'
                                        } />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                )}
            </div>

            {/* Live Feed */}
            <LiveThreatFeed />

            <style>{`
                @keyframes slideDown {
                    from { opacity: 0; transform: translateY(-10px); }
                    to { opacity: 1; transform: none; }
                }
            `}</style>
        </>
    )
}
