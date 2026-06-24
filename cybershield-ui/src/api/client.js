import axios from 'axios'

const api = axios.create({ baseURL: 'http://127.0.0.1:8000/api' })

api.interceptors.request.use(cfg => {
  const tok = localStorage.getItem('access_token')
  if (tok) cfg.headers.Authorization = `Bearer ${tok}`
  return cfg
})

api.interceptors.response.use(r => r, async err => {
  const orig = err.config
  if (err.response?.status === 401 && !orig._retry) {
    orig._retry = true
    try {
      const refresh = localStorage.getItem('refresh_token')
      const { data } = await axios.post('/api/token/refresh/', { refresh })
      localStorage.setItem('access_token', data.access)
      orig.headers.Authorization = `Bearer ${data.access}`
      return api(orig)
    } catch {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
  }
  return Promise.reject(err)
})

export default api

export const auth = {
  login:  d => axios.post('/api/token/', d),
  signup: d => axios.post('/api/auth/signup/', d),
}

export const scans = {
  scanUrl:    (url, forceRefresh = false) =>
    api.post('/scan/url/', { url, force_refresh: forceRefresh }),
  scanBulk:   urls  => api.post('/scan/bulk/', { urls }),
  scanQr:     fd    => api.post('/scan/qr/', fd, { headers: { 'Content-Type': 'multipart/form-data' } }),
  history:    p     => api.get('/history/', { params: p }),
  analytics:  ()    => api.get('/analytics/'),
  report:     id    => api.get(`/report/${id}/`),
  del:        id    => api.delete(`/history/${id}/`),
  clearCache: url   => api.post('/scan/clear-cache/', { url }),
}
