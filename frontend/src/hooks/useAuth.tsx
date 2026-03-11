import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { authApi } from '../api/client'

interface User { username: string; email: string; role: string }
interface AuthCtx { user: User | null; loading: boolean; login: (u: string, p: string) => Promise<void>; logout: () => void }

const AuthContext = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<User | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const stored = localStorage.getItem('soc_user')
        const token = localStorage.getItem('soc_token')
        if (stored && token) {
            setUser(JSON.parse(stored))
        }
        setLoading(false)
    }, [])

    async function login(username: string, password: string) {
        const res = await authApi.login(username, password)
        localStorage.setItem('soc_token', res.data.access_token)
        const me = await authApi.me()
        localStorage.setItem('soc_user', JSON.stringify(me.data))
        setUser(me.data)
    }

    function logout() {
        localStorage.removeItem('soc_token')
        localStorage.removeItem('soc_user')
        setUser(null)
    }

    return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
    const ctx = useContext(AuthContext)
    if (!ctx) throw new Error('useAuth must be inside AuthProvider')
    return ctx
}
