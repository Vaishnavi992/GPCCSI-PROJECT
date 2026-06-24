const MAP = {
  safe:       'badge-safe',
  low_risk:   'badge-low_risk',
  suspicious: 'badge-suspicious',
  high_risk:  'badge-high_risk',
  malicious:  'badge-malicious',
}
const LABELS = { safe:'Safe', low_risk:'Low Risk', suspicious:'Suspicious', high_risk:'High Risk', malicious:'Malicious' }
export default function ThreatBadge({ level }) {
  return (
    <span className={`pill ${MAP[level] || 'badge-safe'}`}>
      {LABELS[level] || level}
    </span>
  )
}
