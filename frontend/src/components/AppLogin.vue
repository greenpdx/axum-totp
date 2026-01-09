<template>
  <div>
    <div>
      <div>
        <input v-model="fname" />
        <input v-model="lname" />
      </div>
      <br />
      <input type="email" v-model="email" /><br />
      <input type="password" v-model="passwd" /><br />
      <button @click="register" :disabled="enreg">Register</button><br />
      <button @click="login" :disabled="enlin">Login</button>
      <span>{{ loginStatus }}</span
      ><br />
      <button @click="generate" :disabled="engen">Generate</button>
      <button @click="profile" :disabled="enabl">Profile</button>
      <br />
      <div class="dualuse">
        <canvas class="canvas" height="200px" width="200px" id="qrimg" ref="qrimg"></canvas>
        <div class="profiletxt">TEXT</div>
      </div>
      <br />
      <input v-model="key" /><br />
      <button @click="verify" :disabled="enver">Verify</button>
      <button @click="validate" :disabled="enval">Validate</button>
      <br />
      <input v-model="able" @change="disable" type="checkbox" :disabled="enabl" />
      <button @click="disable" :disabled="enabl">Disable</button>
      <br />
      <button @click="logout" :disabled="enlo">Logout</button>
    </div>
  </div>
</template>

<style scoped>
.dualuse {
  width: 200px;
  height: 200px;
  position: relative;
}
.canvas {
  z-index: 3;
}
.profiletxt {
  z-index: 1;
}
</style>

<script setup>
import { ref } from 'vue'
import apiClient from '@/api/client'
import QRCode from 'qrcode'
import { userAuthStore } from '@/stores/auth'
const storeUser = userAuthStore()

const emit = defineEmits(['loginuser'])

const fname = ref('')
const lname = ref('')
const email = ref('')
const passwd = ref('')
const key = ref('')
const loginStatus = ref('Not logged in')
const able = ref(false)
const engen = ref(1)
const enval = ref(1)
const enlo = ref(1)
const enver = ref(1)
const enlin = ref(0)
const enreg = ref(0)
const enabl = ref(1)

const URL_REGISTER = '/auth/register'
const URL_LOGIN = '/auth/login'
const URL_GENERATE = '/auth/otp/generate'
const URL_VERIFY = '/auth/otp/verify'
const URL_DISABLE = '/auth/otp/disable'
const URL_VALIDATE = '/auth/otp/validate'
const URL_LOGOUT = '/auth/logout'
const URL_PROFILE = '/auth/profile'

let qr = {}

async function register() {
  const name = fname.value + ' ' + lname.value
  const payload = { name: name, email: email.value, password: passwd.value }

  try {
    const resp = await apiClient.post(URL_REGISTER, payload)
    if (resp.data.status === 'success') {
      loginStatus.value = 'Registered successfully'
    }
  } catch (err) {
    alert('Registration failed: ' + (err.response?.data?.message || err.message))
  }
}

async function profile() {
  try {
    const payload = { session_token: storeUser.sessionToken }
    const resp = await apiClient.post(URL_PROFILE, payload)
    if (resp.data.user) {
      storeUser.setUser(resp.data.user)
    }
  } catch (err) {
    alert('Failed to load profile: ' + (err.response?.data?.message || err.message))
  }
}

async function login() {
  const payload = { email: email.value, password: passwd.value }

  try {
    const resp = await apiClient.post(URL_LOGIN, payload)
    if (resp.data.status !== 'success') {
      alert('Login failed')
      return
    }

    const sessionToken = resp.data.session_token
    const otpEnabled = resp.data.otp_enabled

    // Store session token for authenticated requests
    if (sessionToken) {
      storeUser.setSessionToken(sessionToken)
    }
    storeUser.setOtpEnabled(otpEnabled)

    loginStatus.value = 'Logged in'

    if (otpEnabled) {
      enver.value = 0
    } else {
      engen.value = 0
    }
    enlo.value = 0
    enlin.value = 1
    enreg.value = 1
    enabl.value = otpEnabled ? 0 : 1
    emit('loginuser', { otpEnabled })
  } catch (err) {
    alert('Invalid credentials')
  }
}

async function generate() {
  try {
    const payload = { session_token: storeUser.sessionToken }
    const resp = await apiClient.post(URL_GENERATE, payload)
    qr = resp.data
    const canvas = document.getElementById('qrimg')
    QRCode.toCanvas(canvas, qr.otpauth_url, function (err) {
      if (err) {
        alert('Failed to generate QR code')
      }
    })
    engen.value = 1
    enver.value = 0
  } catch (err) {
    alert('Failed to generate OTP: ' + (err.response?.data?.message || err.message))
  }
}

async function verify() {
  const payload = { session_token: storeUser.sessionToken, otp_token: key.value }

  try {
    const resp = await apiClient.post(URL_VERIFY, payload)
    if (resp.data.otp_verified) {
      enver.value = 1
      enval.value = 0
      enabl.value = 0
      able.value = true
      storeUser.setOtpEnabled(true)
      key.value = '' // Clear OTP token after use
    } else {
      alert('Verification failed')
    }
  } catch (err) {
    alert('Verification failed: ' + (err.response?.data?.message || err.message))
  }
}

async function validate() {
  const payload = { session_token: storeUser.sessionToken, otp_token: key.value }

  try {
    const resp = await apiClient.post(URL_VALIDATE, payload)
    const valid = resp.data.otp_valid
    if (valid) {
      able.value = true
      key.value = '' // Clear OTP token after use
    } else {
      alert('Invalid OTP code')
    }
  } catch (err) {
    alert('Validation failed: ' + (err.response?.data?.message || err.message))
  }
}

async function disable() {
  try {
    const payload = { session_token: storeUser.sessionToken }
    await apiClient.post(URL_DISABLE, payload)
    able.value = false
    enabl.value = 1
    enval.value = 1
    engen.value = 0
    storeUser.setOtpEnabled(false)
  } catch (err) {
    alert('Failed to disable OTP: ' + (err.response?.data?.message || err.message))
  }
}

async function logout() {
  try {
    const payload = { session_token: storeUser.sessionToken }
    await apiClient.post(URL_LOGOUT, payload)
  } catch {
    // Logout even if request fails
  }

  // Clear auth state
  storeUser.clearAuth()
  loginStatus.value = 'Not logged in'

  // Reset UI state
  able.value = false
  enabl.value = 1
  enval.value = 1
  engen.value = 1
  enver.value = 1
  enlin.value = 0
  enlo.value = 1
  enreg.value = 0
  key.value = ''
}
</script>
