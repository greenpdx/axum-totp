import axios from 'axios'
import { userAuthStore } from '@/stores/auth'

const getBaseUrl = () => {
    // When served from the same origin, use empty base URL for relative paths
    return ''
}

const apiClient = axios.create({
    headers: {
        'Content-Type': 'application/json'
    }
})

// Request interceptor - adds auth token to all requests
apiClient.interceptors.request.use(
    (config) => {
        config.baseURL = getBaseUrl()
        const store = userAuthStore()
        if (store.token) {
            config.headers.Authorization = `Bearer ${store.token}`
        }
        return config
    },
    (error) => {
        return Promise.reject(error)
    }
)

// Response interceptor - handles 401 unauthorized
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            const store = userAuthStore()
            store.clearAuth()
        }
        return Promise.reject(error)
    }
)

export default apiClient
