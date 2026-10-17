import axios from 'axios'

// API base URL - in unified stack, nginx routes /id/api/ to shizuha-id backend
const apiBase = import.meta.env.VITE_API_BASE || '/id/api'

const api = axios.create({
  baseURL: apiBase,
  headers: {
    'Content-Type': 'application/json',
  },
})

export default api
