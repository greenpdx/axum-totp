import { defineStore } from 'pinia'

export const userAuthStore = defineStore('user_auth', {
    state: () => {
        return {
            user: null,
            sessionToken: null,
            otpEnabled: false,
        }
    },
    getters: {
        getUser() { return this.user },
        getSessionToken() { return this.sessionToken },
        isAuthenticated() { return !!this.sessionToken },
        isOtpEnabled() { return this.otpEnabled },
    },
    actions: {
        setUser(user) {
            this.user = user
        },
        setSessionToken(token) {
            this.sessionToken = token
        },
        setOtpEnabled(enabled) {
            this.otpEnabled = enabled
        },
        clearAuth() {
            this.user = null
            this.sessionToken = null
            this.otpEnabled = false
        },
    }
}) 
