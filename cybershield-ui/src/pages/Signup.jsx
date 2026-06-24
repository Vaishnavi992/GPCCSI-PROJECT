import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { auth } from '../api/client'

export default function Signup() {
  const [form, setForm] = useState({ username:'', email:'', password:'', password2:'' })
  const [err, setErr]   = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  const submit = async e => {
    e.preventDefault(); setErr('')
    if (form.password !== form.password2) return setErr('Passwords do not match')
    if (form.password.length < 8) return setErr('Password must be at least 8 characters')
    setLoading(true)
    try {
      await auth.signup({ username: form.username, email: form.email, password: form.password })
      const { data } = await auth.login({ username: form.username, password: form.password })
      localStorage.setItem('access_token',  data.access)
      localStorage.setItem('refresh_token', data.refresh)
      localStorage.setItem('username',       form.username)
      nav('/dashboard')
    } catch(e) {
      setErr(e.response?.data?.error || 'Registration failed. Username may be taken.')
    } finally { setLoading(false) }
  }

  const field = (key, label, type='text', ph='') => (
    <div>
      <label className="block text-xs font-semibold text-cyber-text2 mb-1.5">{label}</label>
      <input className="input-field" type={type} placeholder={ph} value={form[key]}
        onChange={e => setForm(f=>({...f,[key]:e.target.value}))} required={key!=='email'} />
    </div>
  )

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyber-accent2/10 rounded-full blur-3xl" />
      </div>
      <div className="w-full max-w-sm relative animate-slide-up">
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyber-accent to-cyber-accent2 flex items-center justify-center mx-auto mb-4 shadow-glow">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-black text-white mb-1">Create account</h1>
          <p className="text-cyber-text2 text-sm">Start detecting threats with AI</p>
        </div>
        <div className="card">
          {err && <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{err}</div>}
          <form onSubmit={submit} className="space-y-4">
            {field('username','Username','text','choose_username')}
            {field('email','Email (optional)','email','you@example.com')}
            {field('password','Password','password','Min 8 characters')}
            {field('password2','Confirm Password','password','Same password again')}
            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-3 text-base">
              {loading ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Creating…</> : 'Create Account'}
            </button>
          </form>
          <p className="mt-4 text-center text-sm text-cyber-text2">
            Have an account? <Link to="/login" className="text-cyber-accent font-semibold hover:underline">Sign in →</Link>
          </p>
        </div>
      </div>
    </div>
  )
}
