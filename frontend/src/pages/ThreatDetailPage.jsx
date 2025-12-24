import { useParams, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'

export default function ThreatDetailPage() {
  const { threatId } = useParams()
  const navigate = useNavigate()

  return (
    <div className="min-h-screen bg-dark-950 grid-bg flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center"
      >
        <h1 className="text-2xl font-bold text-dark-100 mb-4">
          威胁详情
        </h1>
        <p className="text-dark-400 mb-6 font-mono">Threat ID: {threatId}</p>
        <button
          onClick={() => navigate('/')}
          className="btn-cyber"
        >
          返回仪表盘
        </button>
      </motion.div>
    </div>
  )
}
