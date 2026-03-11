import { useState, useEffect, useRef, useCallback } from 'react'
import { alertsApi } from '../api/client'

export interface LiveAlert {
    id: string
    rule_name: string
    severity: string
    host_name: string
    source_ip: string
    mitre_tactic: string
    triggered_at: string
    isNew?: boolean
}

export function useLiveFeed(maxItems = 40) {
    const [feed, setFeed] = useState<LiveAlert[]>([])
    const [newCount, setNewCount] = useState(0)
    const seenIds = useRef<Set<string>>(new Set())
    const initialized = useRef(false)

    const poll = useCallback(async () => {
        try {
            const res = await alertsApi.list({ page: 1, page_size: 20, status: 'open' })
            const items: LiveAlert[] = res.data.items || []

            const fresh = items.filter(a => !seenIds.current.has(a.id))

            if (fresh.length === 0) return

            // On first load, just mark all as seen (don't animate)
            if (!initialized.current) {
                items.forEach(a => seenIds.current.add(a.id))
                setFeed(items.map(a => ({ ...a, isNew: false })))
                initialized.current = true
                return
            }

            // Subsequent polls: mark fresh as new and animate
            fresh.forEach(a => seenIds.current.add(a.id))
            setNewCount(c => c + fresh.length)

            setFeed(prev => {
                const withNew = fresh.map(a => ({ ...a, isNew: true }))
                const combined = [...withNew, ...prev].slice(0, maxItems)
                return combined
            })

            // Remove the isNew flag after animation completes
            setTimeout(() => {
                setFeed(prev => prev.map(a => ({ ...a, isNew: false })))
            }, 2000)
        } catch (_) { }
    }, [maxItems])

    useEffect(() => {
        poll()
        const id = setInterval(poll, 3000)
        return () => clearInterval(id)
    }, [poll])

    const clearNewCount = useCallback(() => setNewCount(0), [])

    return { feed, newCount, clearNewCount }
}

// Animated counter hook
export function useAnimatedNumber(target: number, duration = 600) {
    const [display, setDisplay] = useState(target)
    const prev = useRef(target)

    useEffect(() => {
        if (prev.current === target) return
        const start = prev.current
        const diff = target - start
        const startTime = performance.now()

        const tick = (now: number) => {
            const elapsed = now - startTime
            const progress = Math.min(elapsed / duration, 1)
            // Ease out
            const eased = 1 - Math.pow(1 - progress, 3)
            setDisplay(Math.round(start + diff * eased))
            if (progress < 1) requestAnimationFrame(tick)
        }

        requestAnimationFrame(tick)
        prev.current = target
    }, [target, duration])

    return display
}
