import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Search, Trash2, ExternalLink, Filter, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { scans } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import ThreatBadge from '../components/ThreatBadge'
import Spinner from '../components/Spinner'

const LEVELS = ['safe','low_risk','suspicious','high_risk','malicious']
const LEVEL_LABELS = { safe:'Safe', low_risk:'Low Risk', suspicious:'Suspicious', high_risk:'High Risk', malicious:'Malicious' }

export default function History() {
  const [data, setData]   = useState({ results:[], total:0, page:1, has_next:false })
  const [loading, setLoading] = useState(true)
  const [search, setSearch]   = useState('')
  const [level, setLevel]     = useState('')
  const [page, setPage]       = useState(1)
  const [deleting, setDeleting] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    scans.history({ q:search, level, page, per_page:25 })
      .then(r => setData(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [search, level, page])

  useEffect(() => { load() }, [load])
  useEffect(() => { setPage(1) }, [search, level])

  const del = async id => {
    if (!confirm('Delete this scan?')) return
    setDeleting(id)
    try {
      await scans.del(id)
      setData(d => ({...d, results: d.results.filter(x => x.id !== id), total: d.total - 1}))
    } catch { alert('Delete failed') }
    finally { setDeleting(null) }
  }

  const levelColor = { safe:'text-emerald-400 border-emerald-500/30 bg-emerald-500/5', low_risk:'text-blue-400 border-blue-500/30 bg-blue-500/5', suspicious:'text-amber-400 border-amber-500/30 bg-amber-500/5', high_risk:'text-red-400 border-red-500/30 bg-red-500/5', malicious:'text-purple-400 border-purple-500/30 bg-purple-500/5' }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-black text-white mb-1">Scan History</h1>
          <p className="text-cyber-text2 text-sm">{data.total} total scans</p>
        </div>
        <button onClick={load} className="btn-ghost flex items-center gap-2 text-sm">
          <RefreshCw className="w-3.5 h-3.5"/> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-text3" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            className="input-field pl-9 py-2 text-sm" placeholder="Search URLs…" />
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-cyber-text3" />
          <button onClick={() => setLevel('')}
            className={`text-xs px-3 py-1.5 rounded-full border font-semibold transition-all ${level==='' ? 'bg-cyber-accent/15 text-cyber-accent border-cyber-accent/40' : 'text-cyber-text3 border-white/10 hover:text-white'}`}>
            All
          </button>
          {LEVELS.map(l => (
            <button key={l} onClick={() => setLevel(level===l?'':l)}
              className={`text-xs px-3 py-1.5 rounded-full border font-semibold transition-all ${level===l ? levelColor[l] : 'text-cyber-text3 border-white/10 hover:text-white'}`}>
              {LEVEL_LABELS[l]}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        {loading ? (
          <div className="py-16 flex justify-center"><Spinner size="md" text="Loading…" /></div>
        ) : data.results.length === 0 ? (
          <div className="py-16 text-center text-cyber-text3 text-sm">
            No scans found. <Link to="/scan/url" className="text-cyber-accent">Scan a URL →</Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06]">
                  {['Score','URL','ML Label','Threat','Scanned At',''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] font-bold text-cyber-text3 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {data.results.map(s => (
                  <tr key={s.id} className="hover:bg-white/[0.02] group transition-colors">
                    <td className="px-4 py-3"><RiskGauge score={s.final_risk_score} size="sm"/></td>
                    <td className="px-4 py-3 max-w-xs">
                      <span className="font-mono text-xs text-cyber-text2 block truncate">{s.url}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`pill text-[10px] ${s.ml_label==='benign'?'badge-safe':s.ml_label==='phishing'||s.ml_label==='malware'?'badge-malicious':'badge-suspicious'}`}>
                        {s.ml_label}
                      </span>
                    </td>
                    <td className="px-4 py-3"><ThreatBadge level={s.threat_level}/></td>
                    <td className="px-4 py-3 text-xs text-cyber-text3 whitespace-nowrap">
                      {new Date(s.submitted_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Link to={`/report/${s.id}`}
                          className="p-1.5 rounded-lg bg-cyber-accent/10 text-cyber-accent hover:bg-cyber-accent/20 transition-colors">
                          <ExternalLink className="w-3.5 h-3.5"/>
                        </Link>
                        <button disabled={deleting===s.id} onClick={() => del(s.id)}
                          className="p-1.5 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-40">
                          <Trash2 className="w-3.5 h-3.5"/>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data.total > 25 && (
          <div className="px-4 py-3 border-t border-white/[0.06] flex items-center justify-between">
            <p className="text-xs text-cyber-text3">
              Showing {((page-1)*25)+1}–{Math.min(page*25, data.total)} of {data.total}
            </p>
            <div className="flex gap-2">
              <button disabled={page===1} onClick={() => setPage(p=>p-1)}
                className="p-1.5 rounded-lg border border-white/10 text-cyber-text2 hover:border-cyber-accent hover:text-cyber-accent disabled:opacity-40 transition-all">
                <ChevronLeft className="w-4 h-4"/>
              </button>
              <span className="px-3 py-1.5 text-xs text-white font-semibold">{page}</span>
              <button disabled={!data.has_next} onClick={() => setPage(p=>p+1)}
                className="p-1.5 rounded-lg border border-white/10 text-cyber-text2 hover:border-cyber-accent hover:text-cyber-accent disabled:opacity-40 transition-all">
                <ChevronRight className="w-4 h-4"/>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
