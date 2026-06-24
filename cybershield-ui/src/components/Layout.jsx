import { NavLink, useNavigate } from 'react-router-dom'
import { Shield, Search, QrCode, Clock, BarChart2, LogOut, Menu, X, List } from 'lucide-react'
import { useState } from 'react'

const links = [
  { to:'/dashboard',   label:'Dashboard',     icon: BarChart2 },
  { to:'/scan/url',    label:'URL Scanner',   icon: Search    },
  { to:'/scan/bulk',   label:'Bulk Scanner',  icon: List      },
  { to:'/scan/qr',     label:'QR Scanner',    icon: QrCode    },
  { to:'/history',     label:'History',       icon: Clock     },
  { to:'/analytics',   label:'Analytics',     icon: BarChart2 },
]

export default function Layout({ children }) {
  const nav  = useNavigate()
  const [open, setOpen] = useState(false)
  const user = localStorage.getItem('username') || 'User'

  const logout = () => { localStorage.clear(); nav('/login') }

  return (
    <div className="min-h-screen bg-cyber-bg flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-60 bg-cyber-bg2 border-r border-white/[0.06]
        flex flex-col transition-transform duration-300
        ${open ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}>

        <div className="flex items-center gap-3 px-5 h-16 border-b border-white/[0.06]">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyber-accent to-cyber-accent2
            flex items-center justify-center flex-shrink-0">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <span className="font-black text-lg tracking-tight">
            Cyber<span className="text-cyber-accent">Shield</span>
          </span>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
          <p className="px-3 py-2 text-[10px] font-bold text-cyber-text3 uppercase tracking-widest">Platform</p>
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150
                 ${isActive
                   ? 'bg-cyber-accent/15 text-white'
                   : 'text-cyber-text2 hover:bg-white/[0.04] hover:text-white'}`}>
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Model status badge */}
        <div className="px-4 pb-2">
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-3 py-2">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">Model Active</span>
            </div>
            <p className="text-[10px] text-cyber-text3 font-mono">XGB+LGB+CAT · 96.80%</p>
            <p className="text-[10px] text-cyber-text3 font-mono">2.18M URLs · 59 features</p>
          </div>
        </div>

        {/* User footer */}
        <div className="p-3 border-t border-white/[0.06]">
          <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-white/[0.03]">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-cyber-accent to-cyber-accent2
              flex items-center justify-center text-xs font-black text-white flex-shrink-0">
              {user[0]?.toUpperCase()}
            </div>
            <span className="text-sm font-medium text-cyber-text2 flex-1 truncate">{user}</span>
            <button onClick={logout} className="text-cyber-text3 hover:text-red-400 transition-colors" title="Sign out">
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {open && <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setOpen(false)} />}

      {/* Main */}
      <div className="flex-1 flex flex-col min-h-screen lg:pl-60">
        <header className="sticky top-0 z-30 h-14 bg-cyber-bg/80 backdrop-blur-xl
          border-b border-white/[0.06] flex items-center px-4 gap-4">
          <button className="lg:hidden text-cyber-text2" onClick={() => setOpen(v => !v)}>
            {open ? <X className="w-5 h-5"/> : <Menu className="w-5 h-5"/>}
          </button>
          <div className="ml-auto flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs text-cyber-text3 font-mono hidden sm:block">AUC 99.61% · Cached scans enabled</span>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl w-full mx-auto animate-fade-in">
          {children}
        </main>
      </div>
    </div>
  )
}
