export default function Spinner({ size='sm', text='' }) {
  const s = size==='lg' ? 'w-12 h-12 border-4' : size==='md' ? 'w-7 h-7 border-2' : 'w-4 h-4 border-2'
  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div className={`${s} border-cyber-accent/30 border-t-cyber-accent rounded-full animate-spin`} />
      {text && <p className="text-cyber-text2 text-sm">{text}</p>}
    </div>
  )
}
