export function riskConfig(score) {
  if (score <= 20)  return { color:'#10b981', label:'Safe',       emoji:'🟢', cls:'badge-safe',       gradient:'from-emerald-500 to-emerald-700' }
  if (score <= 40)  return { color:'#3b82f6', label:'Low Risk',   emoji:'🔵', cls:'badge-low_risk',   gradient:'from-blue-500 to-blue-700' }
  if (score <= 60)  return { color:'#f59e0b', label:'Suspicious', emoji:'🟡', cls:'badge-suspicious', gradient:'from-amber-500 to-amber-700' }
  if (score <= 80)  return { color:'#ef4444', label:'High Risk',  emoji:'🔴', cls:'badge-high_risk',  gradient:'from-red-500 to-red-700' }
  return             { color:'#a855f7', label:'Malicious',  emoji:'☠️', cls:'badge-malicious', gradient:'from-purple-500 to-purple-700' }
}

export default function RiskGauge({ score, size = 'lg' }) {
  const cfg = riskConfig(score)
  const sz  = size === 'lg' ? 'w-32 h-32 text-4xl' : size === 'md' ? 'w-20 h-20 text-2xl' : 'w-10 h-10 text-sm'

  return (
    <div className={`${sz} rounded-full bg-gradient-to-br ${cfg.gradient} flex flex-col items-center justify-center shadow-xl flex-shrink-0`}>
      <span className={`font-black text-white ${size==='sm'?'text-xs':''} leading-none`}>{score}</span>
      {size !== 'sm' && <span className="text-white/70 text-[10px] uppercase tracking-wide">/100</span>}
    </div>
  )
}
