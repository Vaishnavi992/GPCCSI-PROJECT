import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, AreaChart, Area, Legend } from 'recharts'
import { TrendingUp, Target, Shield, AlertTriangle } from 'lucide-react'
import { scans } from '../api/client'
import Spinner from '../components/Spinner'

const TC = { safe:'#10b981', low_risk:'#3b82f6', suspicious:'#f59e0b', high_risk:'#ef4444', malicious:'#a855f7' }
const ML = { benign:'#10b981', defacement:'#f59e0b', malware:'#a855f7', phishing:'#ef4444' }
const TL = { safe:'Safe', low_risk:'Low Risk', suspicious:'Suspicious', high_risk:'High Risk', malicious:'Malicious' }

const Tip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-cyber-card2 border border-white/10 rounded-xl px-3 py-2 text-xs shadow-xl">
      <p className="text-cyber-text3 mb-1">{label}</p>
      {payload.map((p,i) => <p key={i} style={{color:p.color}} className="font-bold">{p.name}: {p.value}</p>)}
    </div>
  )
}

function ChartCard({ title, icon: Icon, children }) {
  return (
    <div className="card">
      <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
        <div className="w-6 h-6 rounded-lg bg-cyber-accent/10 flex items-center justify-center">
          <Icon className="w-3.5 h-3.5 text-cyber-accent" />
        </div>
        {title}
      </h3>
      {children}
    </div>
  )
}

export default function Analytics() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    scans.analytics().then(r => setData(r.data)).catch(console.error).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner size="lg" text="Loading analytics…" /></div>

  if (!data?.total) return (
    <div className="text-center py-24">
      <Shield className="w-12 h-12 text-cyber-text3 mx-auto mb-4" />
      <h2 className="text-lg font-bold text-white mb-2">No data yet</h2>
      <p className="text-cyber-text2 text-sm">Start scanning URLs to see analytics here.</p>
    </div>
  )

  const threatData = (data.by_threat || []).map(t => ({ name: TL[t.threat_level] || t.threat_level, value: t.count, color: TC[t.threat_level] || '#6b7a9e' }))
  const mlData     = (data.by_ml_label || []).map(t => ({ name: t.ml_label, value: t.count, color: ML[t.ml_label] || '#6b7a9e' }))
  const dailyData  = (data.daily || []).map(d => ({ ...d, date: d.day?.slice(5) || d.day }))

  const malCount = (data.by_threat || []).filter(t => ['malicious','high_risk'].includes(t.threat_level)).reduce((s,t)=>s+t.count,0)
  const safeCount = (data.by_threat || []).find(t=>t.threat_level==='safe')?.count || 0

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-white mb-1">Analytics</h1>
        <p className="text-cyber-text2 text-sm">Security intelligence from {data.total?.toLocaleString()} scans.</p>
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label:'Total Scans',    value: data.total?.toLocaleString(), icon: Shield,       color:'text-cyber-accent',   border:'border-cyber-accent/20' },
          { label:'Avg Risk Score', value: Math.round(data.avg_risk||0), icon: Target,       color:'text-amber-400',      border:'border-amber-500/20' },
          { label:'Threats Found',  value: malCount,                     icon: AlertTriangle, color:'text-red-400',        border:'border-red-500/20' },
          { label:'Safe URLs',      value: safeCount,                    icon: Shield,       color:'text-emerald-400',    border:'border-emerald-500/20' },
        ].map(s => (
          <div key={s.label} className={`card border ${s.border}`}>
            <s.icon className={`w-5 h-5 mb-2 ${s.color}`} />
            <div className={`text-3xl font-black ${s.color} mb-0.5`}>{s.value}</div>
            <div className="text-xs text-cyber-text2 font-semibold">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Trend chart */}
      {dailyData.length > 0 && (
        <ChartCard title="Scan Volume — Last 30 Days" icon={TrendingUp}>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={dailyData}>
              <defs>
                <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#4f7cff" stopOpacity={0.35}/>
                  <stop offset="95%" stopColor="#4f7cff" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{fill:'#6b7a9e',fontSize:10}} tickLine={false} axisLine={false}/>
              <YAxis tick={{fill:'#6b7a9e',fontSize:10}} tickLine={false} axisLine={false} width={28}/>
              <Tooltip content={<Tip/>}/>
              <Area type="monotone" dataKey="count" name="Scans" stroke="#4f7cff" strokeWidth={2} fill="url(#ag)"/>
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
      )}

      {/* Pie + Bar side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="Threat Level Distribution" icon={Shield}>
          {threatData.length > 0 ? (
            <div className="flex items-center gap-6">
              <PieChart width={160} height={160}>
                <Pie data={threatData} dataKey="value" cx={75} cy={75} innerRadius={44} outerRadius={70} paddingAngle={3}>
                  {threatData.map((d,i) => <Cell key={i} fill={d.color}/>)}
                </Pie>
                <Tooltip formatter={(v,n)=>[v,n]}/>
              </PieChart>
              <div className="flex-1 space-y-2">
                {threatData.map(d => (
                  <div key={d.name} className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{background:d.color}}/>
                    <span className="text-xs text-cyber-text2 flex-1">{d.name}</span>
                    <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{width:`${d.value/data.total*100}%`,background:d.color}}/>
                    </div>
                    <span className="text-xs font-bold font-mono w-8 text-right" style={{color:d.color}}>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : <p className="text-cyber-text3 text-sm text-center py-8">No data</p>}
        </ChartCard>

        <ChartCard title="ML Model Predictions" icon={Target}>
          {mlData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={mlData} barSize={32}>
                <XAxis dataKey="name" tick={{fill:'#6b7a9e',fontSize:11}} tickLine={false} axisLine={false}/>
                <YAxis tick={{fill:'#6b7a9e',fontSize:10}} tickLine={false} axisLine={false} width={28}/>
                <Tooltip content={<Tip/>}/>
                <Bar dataKey="value" name="Count" radius={[6,6,0,0]}>
                  {mlData.map((d,i) => <Cell key={i} fill={d.color}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-cyber-text3 text-sm text-center py-8">No data</p>}
        </ChartCard>
      </div>

      {/* Top threats table */}
      {data.top_threats?.length > 0 && (
        <div className="card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.06]">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400"/> Top Threats Detected
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.05]">
                  {['URL','ML Label','Risk Score','Threat','Date'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-[10px] font-bold text-cyber-text3 uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03]">
                {data.top_threats.map(s => (
                  <tr key={s.id} className="hover:bg-white/[0.02]">
                    <td className="px-4 py-3 max-w-[250px]"><span className="font-mono text-cyber-text2 truncate block">{s.url}</span></td>
                    <td className="px-4 py-3"><span className="pill badge-malicious">{s.ml_label}</span></td>
                    <td className="px-4 py-3 font-black font-mono" style={{color: s.final_risk_score>80?'#a855f7':'#ef4444'}}>{s.final_risk_score}/100</td>
                    <td className="px-4 py-3"><span className={`pill badge-${s.threat_level}`}>{s.threat_level.replace('_',' ')}</span></td>
                    <td className="px-4 py-3 text-cyber-text3 whitespace-nowrap">{new Date(s.submitted_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
