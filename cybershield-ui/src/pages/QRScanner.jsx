import { useState, useRef } from 'react'
import { QrCode, Upload, X, CheckCircle, AlertTriangle } from 'lucide-react'
import { scans } from '../api/client'
import RiskGauge, { riskConfig } from '../components/RiskGauge'
import Spinner from '../components/Spinner'

export default function QRScanner() {
  const [files, setFiles]     = useState([])
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [drag, setDrag]       = useState(false)
  const inputRef              = useRef()

  const addFiles = fs => {
    const valid = [...fs].filter(f => f.type.startsWith('image/'))
    setFiles(prev => [...prev, ...valid].slice(0, 20))
  }

  const removeFile = i => setFiles(f => f.filter((_,idx)=>idx!==i))

  const scan = async () => {
    if (!files.length) return
    setLoading(true); setResults([])
    const fd = new FormData()
    files.forEach(f => fd.append('qr_images', f))
    try {
      const { data } = await scans.scanQr(fd)
      setResults(Array.isArray(data) ? data : [data])
    } catch(e) {
      setResults([{ error: e.response?.data?.error || 'Scan failed' }])
    } finally { setLoading(false) }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-black text-white mb-1">QR Scanner</h1>
        <p className="text-cyber-text2 text-sm">Upload QR code images — decoded URL is automatically scanned for threats.</p>
      </div>

      {/* Drop zone */}
      <div className="card">
        <div
          onDragOver={e=>{e.preventDefault();setDrag(true)}}
          onDragLeave={()=>setDrag(false)}
          onDrop={e=>{e.preventDefault();setDrag(false);addFiles(e.dataTransfer.files)}}
          onClick={()=>inputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all duration-200
            ${drag ? 'border-cyber-accent bg-cyber-accent/5' : 'border-white/10 hover:border-cyber-accent/50 hover:bg-white/[0.02]'}`}>
          <div className="w-14 h-14 rounded-2xl bg-cyber-accent/10 flex items-center justify-center mx-auto mb-4">
            <QrCode className="w-7 h-7 text-cyber-accent" />
          </div>
          <p className="text-white font-semibold mb-1">Drop QR code images here</p>
          <p className="text-cyber-text2 text-sm mb-4">PNG, JPEG, WebP — up to 20 images at once</p>
          <span className="btn-ghost cursor-pointer inline-flex items-center gap-2">
            <Upload className="w-4 h-4" /> Choose Files
          </span>
          <input ref={inputRef} type="file" className="hidden" multiple accept="image/*"
            onChange={e=>addFiles(e.target.files)} />
        </div>

        {/* File chips */}
        {files.length > 0 && (
          <div className="mt-4">
            <div className="flex flex-wrap gap-2 mb-4">
              {files.map((f,i) => (
                <div key={i} className="flex items-center gap-1.5 bg-cyber-accent/10 border border-cyber-accent/30 rounded-full pl-3 pr-1 py-1">
                  <span className="text-xs font-mono text-cyber-accent max-w-[180px] truncate">{f.name}</span>
                  <button onClick={e=>{e.stopPropagation();removeFile(i)}}
                    className="w-4 h-4 rounded-full bg-cyber-accent/20 flex items-center justify-center text-cyber-accent hover:bg-red-500/20 hover:text-red-400 transition-colors">
                    <X className="w-2.5 h-2.5"/>
                  </button>
                </div>
              ))}
            </div>
            <button onClick={scan} disabled={loading}
              className="btn-primary">
              {loading
                ? <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Scanning {files.length} image{files.length>1?'s':''}…</>
                : <><QrCode className="w-4 h-4"/>Scan {files.length} QR Code{files.length>1?'s':''}</>}
            </button>
          </div>
        )}
      </div>

      {loading && (
        <div className="card flex flex-col items-center py-14">
          <Spinner size="lg" text="Decoding QR codes and scanning embedded URLs…" />
        </div>
      )}

      {/* Results */}
      {results.map((r, i) => (
        <div key={i} className="card animate-slide-up space-y-4">
          {/* File header */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyber-accent2/10 flex items-center justify-center flex-shrink-0">
              <QrCode className="w-5 h-5 text-cyber-accent2" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-semibold text-white text-sm truncate">{r.filename || `Image ${i+1}`}</p>
              {r.decode?.success
                ? <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-bold"><CheckCircle className="w-3 h-3"/>Decoded via {r.decode.method}</span>
                : <span className="inline-flex items-center gap-1 text-[10px] text-red-400 font-bold"><AlertTriangle className="w-3 h-3"/>Decode failed</span>}
            </div>
          </div>

          {r.error && <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">⚠️ {r.error}</div>}

          {r.decode?.success && (
            <div className="bg-cyber-bg3 rounded-lg px-3 py-2 font-mono text-xs text-cyber-text2 break-all">
              <span className="text-cyber-text3">Decoded URL: </span>{r.decode.data}
            </div>
          )}

          {r.scan && (() => {
            const cfg = riskConfig(r.scan.final_risk_score)
            return (
              <div className="bg-cyber-bg3 border border-white/[0.06] rounded-xl p-4 flex gap-4 items-start">
                <RiskGauge score={r.scan.final_risk_score} size="md" />
                <div className="flex-1 min-w-0">
                  <div className="text-xl font-black mb-1" style={{color:cfg.color}}>{cfg.emoji} {r.scan.threat_level}</div>
                  <p className="text-xs text-cyber-text2 mb-2">ML: <strong className="text-white">{r.scan.ml_prediction?.label?.toUpperCase()}</strong> · {(r.scan.ml_prediction?.confidence*100).toFixed(0)}% confidence</p>
                  <p className="text-xs text-cyber-text bg-cyber-bg px-3 py-2 rounded-lg border-l-2" style={{borderColor:cfg.color}}>💡 {r.scan.recommendation}</p>
                </div>
              </div>
            )
          })()}
        </div>
      ))}
    </div>
  )
}
