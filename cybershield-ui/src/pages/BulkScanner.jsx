import { useState } from 'react'
import { List, Zap, RefreshCw, Download, CheckCircle, AlertTriangle, XCircle } from 'lucide-react'
import { scans } from '../api/client'
import RiskGauge, { riskConfig } from '../components/RiskGauge'
import Spinner from '../components/Spinner'

const PLACEHOLDER = `https://google.com
http://paypal-secure-verify.tk/login
https://github.com
http://free-bitcoin-prize.xyz/win
https://stackoverflow.com`

function ResultRow({ r, i }) {
  if (r.error) return (
    <div className="flex items-center gap-3 p-3 bg-red-500/5 border border-red-500/20 rounded-xl">
      <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
      <span className="font-mono text-xs text-cyber-text2 flex-1 truncate">{r.url || `Row ${i+1}`}</span>
      <span className="text-xs text-red-400">{r.error}</span>
    </div>
  )

  const cfg = riskConfig(r.final_risk_score)
  const Icon = r.final_risk_score <= 20 ? CheckCircle : r.final_risk_score <= 40 ? CheckCircle : AlertTriangle

  return (
    <div className="flex items-center gap-3 p-3 bg-cyber-bg3 border border-white/[0.05] hover:border-white/10 rounded-xl transition-all">
      <RiskGauge score={r.final_risk_score} size="sm" />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-xs text-cyber-text2 truncate">{r.url}</div>
        <div className="flex items-center gap-2 mt-1">
          <span className={`pill text-[10px] ${r.ml_prediction?.label==='benign'?'badge-safe':'badge-malicious'}`}>
            {r.ml_prediction?.label}
          </span>
          {r.from_cache && (
            <span className="text-[10px] text-cyber-text3 flex items-center gap-0.5">
              <RefreshCw className="w-2.5 h-2.5"/> cached
            </span>
          )}
        </div>
      </div>
      <div className="text-right flex-shrink-0">
        <div className="text-sm font-black" style={{color: cfg.color}}>{r.final_risk_score}</div>
        <div className="text-[10px] text-cyber-text3">{cfg.label}</div>
      </div>
    </div>
  )
}

export default function BulkScanner() {
  const [text, setText]       = useState('')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [err, setErr]         = useState('')
  const [stats, setStats]     = useState(null)

  const urls = text.split('\n').map(l => l.trim()).filter(Boolean)

  const scan = async () => {
    if (!urls.length) return setErr('Enter at least one URL')
    if (urls.length > 20) return setErr('Maximum 20 URLs per bulk scan')
    setLoading(true); setErr(''); setResults([])
    try {
      const { data } = await scans.scanBulk(urls)
      setResults(data)
      const s = data.filter(r => !r.error)
      setStats({
        total:     data.length,
        safe:      s.filter(r => r.final_risk_score <= 20).length,
        suspicious:s.filter(r => r.final_risk_score > 20 && r.final_risk_score <= 60).length,
        dangerous: s.filter(r => r.final_risk_score > 60).length,
        cached:    s.filter(r => r.from_cache).length,
      })
    } catch(e) {
      setErr(e.response?.data?.error || 'Bulk scan failed')
    } finally { setLoading(false) }
  }

  const exportCSV = () => {
    const rows = [['URL','ML Label','Risk Score','Threat Level','Recommendation']]
    results.forEach(r => {
      if (!r.error) rows.push([
        r.url, r.ml_prediction?.label, r.final_risk_score,
        r.threat_level, r.recommendation
      ])
    })
    const csv  = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n')
    const blob = new Blob([csv], {type:'text/csv'})
    const a    = document.createElement('a')
    a.href     = URL.createObjectURL(blob)
    a.download = `cybershield_bulk_${Date.now()}.csv`
    a.click()
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-white mb-1">Bulk URL Scanner</h1>
        <p className="text-cyber-text2 text-sm">Paste up to 20 URLs (one per line) — scanned simultaneously with ML + threat intelligence.</p>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <label className="text-sm font-semibold text-cyber-text2 flex items-center gap-2">
            <List className="w-4 h-4"/> URLs to scan
            <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${urls.length > 20 ? 'bg-red-500/20 text-red-400' : 'bg-white/5 text-cyber-text3'}`}>
              {urls.length}/20
            </span>
          </label>
          <button onClick={() => setText(PLACEHOLDER)} className="text-xs text-cyber-accent hover:underline">
            Load examples
          </button>
        </div>
        <textarea
          value={text} onChange={e => setText(e.target.value)}
          rows={8} placeholder={PLACEHOLDER}
          className="w-full bg-cyber-bg3 border border-white/[0.08] rounded-xl px-4 py-3
                     font-mono text-xs text-cyber-text placeholder-cyber-text3 outline-none
                     focus:border-cyber-accent resize-none transition-all
                     focus:shadow-[0_0_0_3px_rgba(79,124,255,0.15)]"
        />
        {err && <p className="mt-2 text-sm text-red-400">⚠️ {err}</p>}
        <div className="flex gap-3 mt-4">
          <button onClick={scan} disabled={loading || !urls.length || urls.length > 20}
            className="btn-primary">
            {loading
              ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Scanning {urls.length} URL{urls.length!==1?'s':''}…</>
              : <><Zap className="w-4 h-4"/>Scan {urls.length || 0} URL{urls.length!==1?'s':''}</>}
          </button>
          {results.length > 0 && (
            <button onClick={exportCSV} className="btn-ghost flex items-center gap-2 text-sm">
              <Download className="w-4 h-4"/> Export CSV
            </button>
          )}
        </div>
      </div>

      {loading && (
        <div className="card flex flex-col items-center py-16">
          <Spinner size="lg" text={`Scanning ${urls.length} URLs in parallel…`} />
          <p className="text-xs text-cyber-text3 mt-3">ML model + threat intelligence APIs running concurrently</p>
        </div>
      )}

      {stats && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label:'Total', val:stats.total,     color:'text-cyber-accent' },
            { label:'Safe',  val:stats.safe,       color:'text-emerald-400' },
            { label:'Suspicious', val:stats.suspicious, color:'text-amber-400' },
            { label:'Dangerous', val:stats.dangerous, color:'text-red-400' },
          ].map(s => (
            <div key={s.label} className="card-sm text-center">
              <div className={`text-2xl font-black ${s.color}`}>{s.val}</div>
              <div className="text-xs text-cyber-text3 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {results.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-bold text-white mb-4">
            Results — {results.length} URL{results.length !== 1 ? 's' : ''}
            {stats?.cached > 0 && (
              <span className="ml-2 text-xs text-cyber-text3 font-normal">
                ({stats.cached} from cache)
              </span>
            )}
          </h3>
          <div className="space-y-2">
            {results.map((r, i) => <ResultRow key={i} r={r} i={i} />)}
          </div>
        </div>
      )}
    </div>
  )
}
