import axios from 'axios'

const api = axios.create({
    baseURL: '/api/v1',
    timeout: 10000,
})

// Attach JWT on every request
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('soc_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
})

// Auto-logout on 401
api.interceptors.response.use(
    (r) => r,
    (err) => {
        if (err.response?.status === 401) {
            localStorage.removeItem('soc_token')
            localStorage.removeItem('soc_user')
            window.location.href = '/login'
        }
        return Promise.reject(err)
    }
)

export const authApi = {
    login: (username: string, password: string) =>
        api.post('/auth/login', new URLSearchParams({ username, password }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
    me: () => api.get('/auth/me'),
}

export const alertsApi = {
    list: (params?: object) => api.get('/alerts', { params }),
    get: (id: string) => api.get(`/alerts/${id}`),
    acknowledge: (id: string) => api.post(`/alerts/${id}/acknowledge`),
    falsePositive: (id: string) => api.post(`/alerts/${id}/false-positive`),
}

export const incidentsApi = {
    list: (params?: object) => api.get('/incidents', { params }),
    get: (id: string) => api.get(`/incidents/${id}`),
    create: (data: object) => api.post('/incidents', data),
    updateStatus: (id: string, data: object) => api.put(`/incidents/${id}/status`, data),
}

export const metricsApi = {
    kpi: (days = 7) => api.get('/metrics/kpi', { params: { days } }),
    alertVolume: (days = 7) => api.get('/metrics/alert-volume', { params: { days } }),
    attackHeatmap: (days = 7) => api.get('/metrics/attack-heatmap', { params: { days } })
}

export const rulesApi = {
    list: () => api.get('/rules'),
    toggle: (id: string, enabled: boolean) => api.put(`/rules/${id}`, { enabled })
}

export const settingsApi = {
    get: () => api.get('/settings'),
    update: (data: object) => api.put('/settings', data)
}

export const playbooksApi = {
    list: () => api.get('/playbooks'),
    execute: (id: string) => api.put(`/playbooks/${id}/execute`)
}

export const simulationApi = {
    trigger: (scenario: string) => api.post('/simulate', { scenario })
}

export default api
