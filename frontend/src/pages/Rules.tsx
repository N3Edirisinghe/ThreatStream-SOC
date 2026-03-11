import { useState, useEffect } from 'react'
import { BookOpen, Shield, ShieldCheck, Zap } from 'lucide-react'
import { rulesApi } from '../api/client'

interface Rule {
    rule_id: string; name: string; severity: string;
    mitre_tactic: string; mitre_technique: string; enabled: boolean;
}

export default function RulesPage() {
    const [rules, setRules] = useState<Rule[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        rulesApi.list()
            .then(res => setRules(res.data))
            .catch(() => { })
            .finally(() => setLoading(false))
    }, [])

    const toggleRule = async (id: string, currentEnabled: boolean) => {
        try {
            await rulesApi.toggle(id, !currentEnabled)
            setRules(prev => prev.map(r => r.rule_id === id ? { ...r, enabled: !currentEnabled } : r))
        } catch { }
    }

    return (
        <>
            <div className="page-header">
                <BookOpen size={18} color="var(--neon-blue)" style={{ filter: 'drop-shadow(0 0 6px var(--neon-blue))' }} />
                <h2 className="page-title">Detection Rules</h2>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {rules.length} active signatures
                </span>
            </div>

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                {loading && (
                    <div style={{ padding: 40, textAlign: 'center', color: 'var(--neon-cyan)', fontFamily: 'var(--font-mono)' }}>
                        <Zap size={20} className="pulse" style={{ marginBottom: 10 }} />
                        QUERYING SIGNATURE DATABASE...
                    </div>
                )}

                {!loading && (
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Severity</th>
                                <th>ID</th>
                                <th>Name</th>
                                <th>ATT&CK Tactic</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.map(rule => (
                                <tr key={rule.rule_id} style={{ opacity: rule.enabled ? 1 : 0.6 }}>
                                    <td>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                            {rule.enabled ?
                                                <ShieldCheck size={14} color="var(--neon-green)" /> :
                                                <Shield size={14} color="var(--text-ghost)" />
                                            }
                                            <span style={{
                                                color: rule.enabled ? 'var(--neon-green)' : 'var(--text-ghost)',
                                                fontSize: '0.65rem', fontWeight: 700, fontFamily: 'var(--font-mono)'
                                            }}>
                                                {rule.enabled ? 'ACTIVE' : 'STAGED'}
                                            </span>
                                        </div>
                                    </td>
                                    <td><span className={`badge badge-${rule.severity}`}>{rule.severity}</span></td>
                                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{rule.rule_id}</td>
                                    <td>
                                        <div style={{ fontWeight: 600, fontSize: '0.85rem', color: rule.enabled ? 'var(--text-bright)' : 'var(--text-muted)' }}>
                                            {rule.name}
                                        </div>
                                        <div style={{ fontSize: '0.65rem', color: 'var(--neon-blue)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                                            {rule.mitre_technique || 'T1500'}
                                        </div>
                                    </td>
                                    <td>
                                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--neon-purple)' }}>
                                            {rule.mitre_tactic}
                                        </span>
                                    </td>
                                    <td>
                                        <button
                                            className="btn btn-ghost btn-sm"
                                            onClick={() => toggleRule(rule.rule_id, rule.enabled)}
                                            style={{ padding: '4px 8px' }}
                                        >
                                            <span style={{
                                                fontFamily: 'var(--font-mono)',
                                                fontSize: '0.65rem',
                                                color: rule.enabled ? 'var(--neon-red)' : 'var(--neon-green)'
                                            }}>
                                                [ {rule.enabled ? 'DEACTIVATE' : 'ACTIVATE'} ]
                                            </span>
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}

                {rules.length === 0 && !loading && (
                    <div style={{ textAlign: 'center', padding: 48, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        NO RULES LOADED
                    </div>
                )}
            </div>
        </>
    )
}
