import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, Shield, Zap, Globe, AlertTriangle, CheckCircle, Code } from 'lucide-react'
import { scans } from '../api/client'
import RiskGauge, { riskConfig } from '../components/RiskGauge'
import ThreatBadge from '../components/ThreatBadge'
import Spinner from '../components/Spinner'

function FeatureItem({ k, v }) {
  const display = v === 1 ? <span className="text-emerald-400 font-bold">Yes</span>
                : v === 0 ? <span className="text-cyber-text3">0</span>
                : <span className="text-white font-mono">{typeof v==='number'?v.toFixed(4).replace(/\.?0+$/,''):v}</span>
  return (
    <div className="bg-cyber-bg3 border border-white/[0.05] rounded-lg p-2.5">
      <div className="text-[10px] text-cyber-text3 font-mono mb-1 truncate">{k}</div>
      <div className="text-sm font-semibold">{display}</div>
    </div>
  )
}

function TICard({ name, emoji, available, score, body, link }) {
  return (
    <div className="card-sm space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold text-white">{emoji} {name}</span>
        <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold border ${available ? 'badge-safe' : 'bg-white/5 text-cyber-text3 border-white/10'}`}>
          {available ? 'Active' : 'No Key'}
        </span>
      </div>
      {available && score !== undefined && (
        <div className={`text-2xl font-black ${score > 50 ? 'text-red-400' : score > 20 ? 'text-amber-400' : 'text-emerald-400'}`}>{score}</div>
      )}
      <p className="text-xs text-cyber-text2">{body || (available ? '—' : 'Add API key in .env to enable')}</p>
      {link && <a href={link} target="_blank" rel="noreferrer" className="text-[10px] text-cyber-accent hover:underline">View full report ↗</a>}
    </div>
  )
}

export default function Report() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')

  useEffect(() => {
    scans.report(id).then(r => setData(r.data)).catch(() => setErr('Report not found.')).finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="flex items-center justify-center h-64"><Spinner size="lg" text="Loading report…"/></div>
  if (err)     return <div className="text-center py-20"><p className="text-red-400">{err}</p><Link to="/history" className="text-cyber-accent text-sm mt-2 block">← Back to History</Link></div>
  if (!data)   return null

  const cfg = riskConfig(data.final_risk_score)
  const vt  = data.threat_intel?.virustotal        || {}
  const gsb = data.threat_intel?.google_safebrowsing || {}
  const pt  = data.threat_intel?.phishtank          || {}
  const ab  = data.threat_intel?.abuseipdb          || {}
  const us  = data.threat_intel?.urlscan            || {}
  const features = data.features || {}
  const heuristic = data.heuristic || {}

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Back */}
      <Link to="/history" className="inline-flex items-center gap-1.5 text-sm text-cyber-text2 hover:text-white transition-colors">
        <ArrowLeft className="w-4 h-4"/> Back to History
      </Link>

      {/* Title */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-black text-white mb-1">Security Report <span className="text-cyber-text3 font-normal">#{id}</span></h1>
          <p className="text-cyber-text2 text-sm">{data.submitted_at ? new Date(data.submitted_at).toLocaleString() : ''}</p>
        </div>
        <ThreatBadge level={data.threat_level} />
      </div>

      {/* Risk Header Card */}
      <div className="card bg-cyber-card2 border-white/10">
        <div className="flex gap-6 items-start flex-wrap">
          <RiskGauge score={data.final_risk_score} size="lg" />
          <div className="flex-1 min-w-0">
            <div className="text-3xl font-black mb-2" style={{color: cfg.color}}>{cfg.emoji} {cfg.label}</div>
            <div className="font-mono text-xs text-cyber-text2 break-all bg-cyber-bg px-3 py-2.5 rounded-xl mb-3">{data.url}</div>
            <div className="flex flex-wrap gap-2 mb-4">
              <span className={`pill ${data.ml_label==='benign'?'badge-safe':'badge-malicious'}`}>ML: {data.ml_label?.toUpperCase()}</span>
              <span className="pill badge-low_risk">{(data.ml_confidence*100).toFixed(1)}% confidence</span>
              <span className="pill badge-suspicious">ML Score: {data.ml_risk_score}/100</span>
            </div>
            {data.recommendation && (
              <div className="bg-cyber-bg3 border-l-4 px-4 py-3 rounded-r-xl text-sm text-cyber-text" style={{borderColor:cfg.color}}>
                💡 {data.recommendation}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Score breakdown */}
      {data.component_scores && (
        <div className="card">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2"><Zap className="w-4 h-4 text-cyber-accent"/>Risk Score Breakdown</h3>
          <div className="space-y-2.5">
            {Object.entries(data.component_scores).map(([k,v]) => {
              const c = v<=20?'#10b981':v<=40?'#3b82f6':v<=60?'#f59e0b':v<=80?'#ef4444':'#a855f7'
              return (
                <div key={k} className="flex items-center gap-3">
                  <span className="text-xs text-cyber-text2 w-40 flex-shrink-0 font-semibold capitalize">{k.replace(/_/g,' ')}</span>
                  <div className="flex-1 h-2 bg-white/[0.06] rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700" style={{width:`${v}%`,background:c}}/>
                  </div>
                  <span className="text-xs font-black font-mono w-8 text-right" style={{color:c}}>{v}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Features + Heuristics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Extracted Features */}
        <div className="card">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <Code className="w-4 h-4 text-cyber-accent"/>
            Extracted URL Features ({Object.keys(features).length})
          </h3>
          <div className="grid grid-cols-2 gap-1.5 max-h-80 overflow-y-auto pr-1">
            {Object.entries(features).map(([k,v]) => <FeatureItem key={k} k={k} v={v}/>)}
          </div>
        </div>

        {/* Heuristic Flags */}
        <div className="card">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400"/>
            Heuristic Analysis
            <span className="ml-auto text-xs font-mono bg-white/5 px-2 py-0.5 rounded-full text-cyber-text3">
              {heuristic.heuristic_score || 0}/100
            </span>
          </h3>
          <ul className="space-y-1.5 max-h-80 overflow-y-auto">
            {(heuristic.flags || []).map((f,i) => (
              <li key={i} className="text-xs bg-cyber-bg3 border border-white/[0.05] rounded-lg px-3 py-2 text-cyber-text">{f}</li>
            ))}
            {!heuristic.flags?.length && <li className="text-cyber-text3 text-sm text-center py-8">No heuristic flags.</li>}
          </ul>
          {heuristic.resolved_ip && (
            <div className="mt-3 text-xs font-mono text-cyber-text2 bg-cyber-bg3 px-3 py-2 rounded-lg">
              Resolved IP: <span className="text-white">{heuristic.resolved_ip}</span>
            </div>
          )}
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="card">
        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2"><Globe className="w-4 h-4 text-cyber-accent"/>Threat Intelligence Results</h3>
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          <TICard name="VirusTotal" emoji="🔍"
            available={vt.available}
            score={vt.risk_score}
            body={vt.available ? `${vt.malicious||0}/${vt.total_engines||0} engines flagged · ${vt.suspicious||0} suspicious` : vt.error}
            link={vt.permalink} />
          <TICard name="Google Safe Browsing" emoji="🛡️"
            available={gsb.available}
            body={gsb.available ? (gsb.is_safe ? '✅ Not in any threat list' : `🚨 ${(gsb.threat_types||[]).join(', ')}`) : gsb.error} />
          <TICard name="PhishTank" emoji="🎣"
            available={pt.available}
            body={pt.available ? (pt.in_database ? `⚠️ In database — verified: ${pt.verified}` : '✅ Not listed') : pt.error} />
          <TICard name="AbuseIPDB" emoji="🌐"
            available={ab.available}
            score={ab.abuse_confidence}
            body={ab.available ? `IP: ${ab.ip_address} · ${ab.country_code} · ${ab.total_reports} reports` : ab.error} />
          <TICard name="URLScan.io" emoji="🔬"
            available={us.available}
            body={us.available ? (us.is_malicious ? '🚨 Flagged malicious' : '✅ Clean') : us.error}
            link={us.result_url} />
        </div>
      </div>
    </div>
  )
}
