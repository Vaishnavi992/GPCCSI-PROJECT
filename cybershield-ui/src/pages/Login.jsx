import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Eye, EyeOff } from 'lucide-react'
import { auth } from '../api/client'

export default function Login() {
  const [form, setForm] = useState({ username:'', password:'' })
  const [err, setErr]   = useState('')
  const [show, setShow] = useState(false)
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  const submit = async e => {
    e.preventDefault(); setErr(''); setLoading(true)
    try {
      const { data } = await auth.login(form)
      localStorage.setItem('access_token',  data.access)
      localStorage.setItem('refresh_token', data.refresh)
      localStorage.setItem('username',       form.username)
      nav('/dashboard')
    } catch {
      setErr('Invalid username or password')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyber-accent/10 rounded-full blur-3xl" />
      </div>
      <div className="w-full max-w-sm relative animate-slide-up">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyber-accent to-cyber-accent2 flex items-center justify-center mx-auto mb-4 shadow-glow">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-black text-white mb-1">Welcome back</h1>
          <p className="text-cyber-text2 text-sm">Sign in to CyberShield</p>
        </div>

        <div className="card">
          {err && (
            <div className="mb-4 p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {err}
            </div>
          )}
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-cyber-text2 mb-1.5">Username</label>
              <input className="input-field" type="text" placeholder="your_username" required
                value={form.username} onChange={e => setForm(f=>({...f,username:e.target.value}))} />
            </div>
            <div>
              <label className="block text-xs font-semibold text-cyber-text2 mb-1.5">Password</label>
              <div className="relative">
                <input className="input-field pr-10" type={show?'text':'password'} placeholder="••••••••" required
                  value={form.password} onChange={e => setForm(f=>({...f,password:e.target.value}))} />
                <button type="button" onClick={()=>setShow(v=>!v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-text3 hover:text-cyber-text">
                  {show ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                </button>
              </div>
            </div>
            <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-3 text-base">
              {loading ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Signing in…</> : 'Sign In'}
            </button>
          </form>
          <p className="mt-4 text-center text-sm text-cyber-text2">
            No account? <Link to="/signup" className="text-cyber-accent font-semibold hover:underline">Create one →</Link>
          </p>
        </div>

        {/* Demo hint */}
        <p className="text-center text-xs text-cyber-text3 mt-4">
          Default: <span className="font-mono">admin / admin123</span>
        </p>
      </div>
    </div>
  )
}
