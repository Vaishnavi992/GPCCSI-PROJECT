import { useState } from 'react'
import { Search, ExternalLink, Shield, AlertTriangle, Zap, RefreshCw, Copy, Check } from 'lucide-react'
import { scans } from '../api/client'
import RiskGauge, { riskConfig } from '../components/RiskGauge'
import Spinner from '../components/Spinner'

const SAMPLES = [
  { url:'https://www.google.com',                   label:'Safe',     cls:'text-emerald-400 border-emerald-500/30 bg-emerald-500/5' },
  { url:'https://github.com',                       label:'Safe',     cls:'text-emerald-400 border-emerald-500/30 bg-emerald-500/5' },
  { url:'http://paypal-secure-verify.tk/login',     label:'Phishing', cls:'text-red-400     border-red-500/30     bg-red-500/5'     },
  { url:'http://192.168.1.1/admin',                 label:'Malware',  cls:'text-red-400     border-red-500/30     bg-red-500/5'     },
]

function ScoreBar({ label, score, color }) {
  return (
    <div className="flex items-center gap-3 py-2 border-b border-white/[0.05] last:border-0">
      <span className="text-xs font-semibold text-cyber-text2 w-44 flex-shrink-0 capitalize">
        {label.replace(/_/g,' ')}
      </span>
      <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700"
          style={{width:`${score}%`, background:color}}/>
      </div>
      <span className="text-xs font-black font-mono w-8 text-right" style={{color}}>{score}</span>
    </div>
  )
}

function TICard({ name, emoji, available, summary, link, error }) {
  return (
    <div className="card-sm flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold text-white">{emoji} {name}</span>
        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold
          ${available ? 'bg-emerald-500/10 text-emerald-400' : 'bg-white/5 text-cyber-text3'}`}>
          {available ? 'Active' : 'No Key'}
        </span>
      </div>
      <p className="text-xs text-cyber-text2">{summary || error || 'Configure API key in .env'}</p>
      {link && <a href={link} target="_blank" rel="noreferrer" className="text-[10px] text-cyber-accent hover:underline">View full report ↗</a>}
    </div>
  )
}

export default function URLScanner() {
  const [url, setUrl]         = useState('')
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr]         = useState('')
  const [copied, setCopied]   = useState(false)

  const scan = async (e, forceRefresh = false) => {
    if (e?.preventDefault) e.preventDefault()
    if (!url.trim()) return
    setLoading(true); setErr(''); setResult(null)
    try {
      const { data } = await scans.scanUrl(url.trim(), forceRefresh)
      setResult(data)
    } catch (e) {
      setErr(e.response?.data?.error || 'Scan failed — is the Django server running on port 8000?')
    } finally { setLoading(false) }
  }

  const copyReport = () => {
    if (!result) return
    const txt = [
      `CyberShield Security Report`,
      `URL: ${result.url}`,
      `Risk Score: ${result.final_risk_score}/100`,
      `Threat Level: ${result.threat_level}`,
      `ML Prediction: ${result.ml_prediction?.label} (${(result.ml_prediction?.confidence*100).toFixed(1)}%)`,
      `Recommendation: ${result.recommendation}`,
    ].join('\n')
    navigator.clipboard.writeText(txt)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const cfg = result ? riskConfig(result.final_risk_score) : null
  const ti  = result?.threat_intel || {}

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-white mb-1">URL Scanner</h1>
        <p className="text-cyber-text2 text-sm">
          XGBoost + LightGBM + CatBoost · 59 features · 5 TI APIs · 2.18M training URLs · 96.80% accuracy
        </p>
      </div>

      <div className="card">
        <form onSubmit={scan} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-text3"/>
            <input value={url} onChange={e => setUrl(e.target.value)}
              className="input-field pl-9" placeholder="https://example.com/path?query=value" required/>
          </div>
          <button type="submit" disabled={loading || !url.trim()} className="btn-primary px-6">
            {loading
              ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Scanning…</>
              : <><Zap className="w-4 h-4"/>Scan</>}
          </button>
        </form>

        <div className="mt-3 flex flex-wrap gap-2 items-center">
          <span className="text-[10px] text-cyber-text3 font-bold uppercase tracking-wider">Try:</span>
          {SAMPLES.map(s => (
            <button key={s.url} onClick={() => setUrl(s.url)}
              className={`text-[10px] font-mono border rounded-full px-2.5 py-1 transition-opacity hover:opacity-80 ${s.cls}`}>
              {s.label}: {s.url.replace(/^https?:\/\//,'').slice(0,28)}
            </button>
          ))}
        </div>
      </div>

      {err && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          ⚠️ {err}
        </div>
      )}

      {loading && (
        <div className="card flex flex-col items-center py-16">
          <Spinner size="lg" text="Running ML model + threat intelligence checks…"/>
          <p className="text-cyber-text3 text-xs mt-3">XGBoost · LightGBM · CatBoost · VirusTotal · GSB · PhishTank · AbuseIPDB · URLScan</p>
        </div>
      )}

      {result && !loading && (
        <div className="space-y-4 animate-slide-up">

          {/* Risk header */}
          <div className="card bg-cyber-card2 border-white/10">
            <div className="flex gap-6 items-start flex-wrap">
              <RiskGauge score={result.final_risk_score}/>
              <div className="flex-1 min-w-0">
                <div className="text-3xl font-black mb-1" style={{color: cfg.color}}>
                  {cfg.emoji} {result.threat_level}
                </div>
                <div className="font-mono text-xs text-cyber-text2 break-all bg-cyber-bg px-3 py-2 rounded-lg mb-3">
                  {result.url}
                </div>
                <div className="flex flex-wrap gap-2 mb-3">
                  <span className={`pill ${result.ml_prediction?.label==='benign'?'badge-safe':'badge-malicious'}`}>
                    ML: {result.ml_prediction?.label?.toUpperCase()}
                  </span>
                  <span className="pill badge-low_risk">
                    {(result.ml_prediction?.confidence*100).toFixed(0)}% confidence
                  </span>
                  {result.ml_prediction?.whitelist_hit && (
                    <span className="pill badge-safe">✓ Trusted Domain</span>
                  )}
                  {result.from_cache && (
                    <span className="pill bg-white/5 text-cyber-text3 border border-white/10 flex items-center gap-1">
                      <RefreshCw className="w-2.5 h-2.5"/>Cached result
                    </span>
                  )}
                </div>
                <div className="bg-cyber-bg3 border-l-4 px-4 py-3 rounded-r-xl text-sm text-cyber-text mb-3"
                  style={{borderColor: cfg.color}}>
                  💡 {result.recommendation}
                </div>
                <div className="flex gap-2 flex-wrap">
                  <button onClick={copyReport}
                    className="btn-ghost flex items-center gap-2 text-xs py-1.5 px-3">
                    {copied ? <><Check className="w-3.5 h-3.5 text-emerald-400"/>Copied!</> : <><Copy className="w-3.5 h-3.5"/>Copy Report</>}
                  </button>
                  {result.from_cache && (
                    <button onClick={() => scan(null, true)}
                      className="btn-ghost flex items-center gap-2 text-xs py-1.5 px-3">
                      <RefreshCw className="w-3.5 h-3.5"/>Force Rescan
                    </button>
                  )}
                  {result.scan_id && (
                    <a href={`/report/${result.scan_id}`}
                      className="btn-ghost flex items-center gap-2 text-xs py-1.5 px-3">
                      <ExternalLink className="w-3.5 h-3.5"/>Full Report
                    </a>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Scores + Probabilities */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="card">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-cyber-accent/20 flex items-center justify-center">
                  <Zap className="w-3 h-3 text-cyber-accent"/>
                </div>
                Component Risk Scores
              </h3>
              {Object.entries(result.component_scores || {}).map(([k,v]) => {
                const c = v<=20?'#10b981':v<=40?'#3b82f6':v<=60?'#f59e0b':v<=80?'#ef4444':'#a855f7'
                return <ScoreBar key={k} label={k} score={v} color={c}/>
              })}
            </div>

            <div className="card">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-purple-500/20 flex items-center justify-center">
                  <Shield className="w-3 h-3 text-purple-400"/>
                </div>
                ML Class Probabilities
              </h3>
              {Object.entries(result.ml_prediction?.probabilities || {}).map(([k,v]) => {
                const cols = {benign:'#10b981',defacement:'#f59e0b',malware:'#a855f7',phishing:'#ef4444'}
                return <ScoreBar key={k} label={k} score={Math.round(v*100)} color={cols[k]||'#4f7cff'}/>
              })}
            </div>
          </div>

          {/* Heuristic flags */}
          {result.heuristic?.flags?.length > 0 && (
            <div className="card">
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <div className="w-5 h-5 rounded bg-amber-500/20 flex items-center justify-center">
                  <AlertTriangle className="w-3 h-3 text-amber-400"/>
                </div>
                Heuristic Security Checks
                <span className="ml-auto text-xs font-mono px-2 py-0.5 rounded-full bg-white/5 text-cyber-text3">
                  {result.heuristic.heuristic_score}/100
                </span>
              </h3>
              <ul className="space-y-1.5">
                {result.heuristic.flags.map((f,i) => (
                  <li key={i} className="text-xs text-cyber-text bg-cyber-bg3 border border-white/[0.06] rounded-lg px-3 py-2">
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* TI APIs */}
          <div className="card">
            <h3 className="text-sm font-bold text-white mb-3">Threat Intelligence APIs</h3>
            <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-2">
              <TICard name="VirusTotal"         emoji="🔍"
                available={ti.virustotal?.available}
                summary={ti.virustotal?.available
                  ? `${ti.virustotal.malicious||0}/${ti.virustotal.total_engines||0} engines flagged`
                  : null}
                link={ti.virustotal?.permalink}
                error={ti.virustotal?.error}/>
              <TICard name="Google Safe Browse" emoji="🛡️"
                available={ti.google_safebrowsing?.available}
                summary={ti.google_safebrowsing?.available
                  ? (ti.google_safebrowsing.is_safe ? '✅ Not listed' : `🚨 ${(ti.google_safebrowsing.threat_types||[]).join(', ')}`)
                  : null}
                error={ti.google_safebrowsing?.error}/>
              <TICard name="PhishTank"          emoji="🎣"
                available={ti.phishtank?.available}
                summary={ti.phishtank?.available
                  ? (ti.phishtank.in_database ? '⚠️ Known phishing URL' : '✅ Not in database')
                  : null}
                error={ti.phishtank?.error}/>
              <TICard name="AbuseIPDB"          emoji="🌐"
                available={ti.abuseipdb?.available}
                summary={ti.abuseipdb?.available
                  ? `IP: ${ti.abuseipdb.ip_address} · ${ti.abuseipdb.abuse_confidence}% abuse score`
                  : null}
                error={ti.abuseipdb?.error}/>
              <TICard name="URLScan.io"         emoji="🔬"
                available={ti.urlscan?.available}
                summary={ti.urlscan?.available
                  ? (ti.urlscan.is_malicious ? '🚨 Flagged malicious' : '✅ Clean')
                  : null}
                link={ti.urlscan?.result_url}
                error={ti.urlscan?.error}/>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
