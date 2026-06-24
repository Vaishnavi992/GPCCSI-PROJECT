import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Search, QrCode, TrendingUp, AlertTriangle, CheckCircle, Clock, List } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { scans } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import ThreatBadge from '../components/ThreatBadge'
import Spinner from '../components/Spinner'

const COLORS = { safe:'#10b981', low_risk:'#3b82f6', suspicious:'#f59e0b', high_risk:'#ef4444', malicious:'#a855f7' }
const LABELS = { safe:'Safe', low_risk:'Low Risk', suspicious:'Suspicious', high_risk:'High Risk', malicious:'Malicious' }

const Tip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-cyber-card2 border border-white/10 rounded-xl px-3 py-2 text-xs shadow-xl">
      <p className="text-cyber-text3 mb-1">{label}</p>
      <p className="text-white font-bold">{payload[0]?.value} scans</p>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, sub, color, border }) {
  return (
    <div className={`card border ${border}`}>
      <div className={`w-9 h-9 rounded-xl flex items-center justify-center mb-3 ${color.replace('text-','bg-').replace('400','500/10').replace('accent','cyber-accent/10')}`}>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className={`text-3xl font-black mb-0.5 ${color}`}>{value ?? '—'}</div>
      <div className="text-xs font-semibold text-cyber-text2">{label}</div>
      {sub && <div className="text-[10px] text-cyber-text3 mt-0.5">{sub}</div>}
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    scans.analytics()
      .then(r => setData(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <Spinner size="lg" text="Loading dashboard…" />
    </div>
  )
  if (!data) return (
    <div className="text-center py-20 text-cyber-text2">Failed to load. Refresh the page.</div>
  )

  const threatDist = (data.by_threat || []).map(t => ({
    ...t,
    name:  LABELS[t.threat_level] || t.threat_level,
    color: COLORS[t.threat_level]  || '#6b7a9e',
  }))
  const safeCount  = (data.by_threat || []).find(t => t.threat_level === 'safe')?.count || 0
  const malCount   = (data.by_threat || [])
    .filter(t => ['malicious','high_risk'].includes(t.threat_level))
    .reduce((s, t) => s + t.count, 0)
  const malPct     = data.total ? Math.round(malCount / data.total * 100) : 0

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-black text-white mb-1">Dashboard</h1>
          <p className="text-cyber-text2 text-sm">
            Welcome back, <strong className="text-white">{localStorage.getItem('username')}</strong>
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Link to="/scan/url"  className="btn-primary"><Search className="w-4 h-4"/>Scan URL</Link>
          <Link to="/scan/bulk" className="btn-ghost flex items-center gap-2 text-sm"><List className="w-4 h-4"/>Bulk Scan</Link>
          <Link to="/scan/qr"   className="btn-ghost flex items-center gap-2 text-sm"><QrCode className="w-4 h-4"/>QR Scan</Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield}        label="Total Scans"      value={data.total?.toLocaleString()} sub="All time"        color="text-cyber-accent"  border="border-cyber-accent/20"/>
        <StatCard icon={AlertTriangle} label="Threats Detected" value={`${malPct}%`}                  sub="High risk +"     color="text-red-400"        border="border-red-500/20"/>
        <StatCard icon={TrendingUp}    label="Avg Risk Score"   value={Math.round(data.avg_risk||0)} sub="Out of 100"      color="text-amber-400"      border="border-amber-500/20"/>
        <StatCard icon={CheckCircle}   label="Safe URLs"        value={safeCount?.toLocaleString()} sub="Confirmed clean" color="text-emerald-400"    border="border-emerald-500/20"/>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Trend */}
        <div className="card lg:col-span-2">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyber-accent"/>Scan Activity — Last 30 Days
          </h3>
          {(data.daily || []).length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={data.daily}>
                <defs>
                  <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#4f7cff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#4f7cff" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" tick={{fill:'#6b7a9e',fontSize:10}} tickLine={false} axisLine={false}/>
                <YAxis  tick={{fill:'#6b7a9e',fontSize:10}} tickLine={false} axisLine={false} width={28}/>
                <Tooltip content={<Tip/>}/>
                <Area type="monotone" dataKey="count" stroke="#4f7cff" strokeWidth={2} fill="url(#ag)"/>
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-44 flex items-center justify-center text-cyber-text3 text-sm">
              No data yet — <Link to="/scan/url" className="text-cyber-accent ml-1">start scanning</Link>
            </div>
          )}
        </div>

        {/* Pie */}
        <div className="card">
          <h3 className="text-sm font-bold text-white mb-4">Threat Distribution</h3>
          {threatDist.length > 0 ? (
            <>
              <PieChart width={160} height={160} style={{margin:'0 auto'}}>
                <Pie data={threatDist} dataKey="count" cx={75} cy={75}
                  innerRadius={45} outerRadius={70} paddingAngle={3}>
                  {threatDist.map((d,i) => <Cell key={i} fill={d.color}/>)}
                </Pie>
                <Tooltip formatter={(v,n) => [v, LABELS[n] || n]}/>
              </PieChart>
              <div className="space-y-1.5 mt-3">
                {threatDist.map(d => (
                  <div key={d.threat_level} className="flex items-center gap-2 text-xs">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background:d.color}}/>
                    <span className="text-cyber-text2 flex-1">{d.name}</span>
                    <span className="font-bold font-mono" style={{color:d.color}}>{d.count}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-cyber-text3 text-sm text-center py-10">No data yet</div>
          )}
        </div>
      </div>

      {/* Recent scans — uses data.recent from analytics endpoint */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyber-accent"/>Recent Scans
          </h3>
          <Link to="/history" className="text-xs text-cyber-accent hover:underline">View all →</Link>
        </div>
        {(data.recent || []).length > 0 ? (
          <div className="space-y-2">
            {data.recent.map(s => (
              <Link key={s.id} to={`/report/${s.id}`}
                className="flex items-center gap-3 p-3 rounded-xl bg-cyber-bg3
                  border border-white/[0.05] hover:border-white/10 transition-all group">
                <RiskGauge score={s.final_risk_score} size="sm"/>
                <div className="flex-1 min-w-0">
                  <div className="font-mono text-xs text-cyber-text2 truncate">{s.url}</div>
                  <div className="text-[10px] text-cyber-text3 mt-0.5">
                    {new Date(s.submitted_at).toLocaleString()} · {s.ml_label}
                  </div>
                </div>
                <ThreatBadge level={s.threat_level}/>
              </Link>
            ))}
          </div>
        ) : (
          <div className="text-center py-10 text-cyber-text3 text-sm">
            No scans yet.{' '}
            <Link to="/scan/url" className="text-cyber-accent">Scan your first URL →</Link>
          </div>
        )}
      </div>
    </div>
  )
}
