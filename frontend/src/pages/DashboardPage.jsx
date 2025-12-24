import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  useThreatStore,
  THREAT_TYPES,
  THREAT_LEVELS,
  generateMockThreat,
  generateMockEdgeNodes,
  generateMockAttackSources,
} from '../store'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

// 图标组件
const Icons = {
  Shield: () => (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  Alert: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  Globe: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  Server: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  ),
  Activity: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  Ban: () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  ),
}

// 统计卡片
const StatCard = ({ title, value, icon: Icon, trend, color = 'cyber' }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className="data-card p-5"
  >
    <div className="flex items-start justify-between mb-3">
      <div className={`p-2 rounded-lg bg-${color}-500/10`}>
        <Icon />
      </div>
      {trend && (
        <span className={`text-xs font-mono ${trend > 0 ? 'text-danger-400' : 'text-cyber-400'}`}>
          {trend > 0 ? '+' : ''}{trend}%
        </span>
      )}
    </div>
    <div className="stat-number text-cyber-400 mb-1">{value.toLocaleString()}</div>
    <div className="text-dark-400 text-sm">{title}</div>
  </motion.div>
)

// 威胁列表项
const ThreatItem = ({ threat }) => {
  const typeInfo = THREAT_TYPES[threat.type]
  const levelInfo = THREAT_LEVELS[threat.level]

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="flex items-center gap-4 p-3 bg-dark-800/50 rounded-lg border border-dark-700 hover:border-dark-600 transition-colors"
    >
      <div className="text-2xl">{typeInfo?.icon}</div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-medium text-dark-100 truncate">{typeInfo?.name}</span>
          <span className={`threat-badge ${threat.level.toLowerCase()}`}>
            {levelInfo?.name}
          </span>
          {threat.blocked && (
            <span className="threat-badge low">已拦截</span>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs text-dark-400 font-mono">
          <span>{threat.sourceIp}</span>
          <span>→</span>
          <span>{threat.targetPath}</span>
        </div>
      </div>
      <div className="text-xs text-dark-500 font-mono">
        {new Date(threat.timestamp).toLocaleTimeString()}
      </div>
    </motion.div>
  )
}

// 边缘节点状态
const EdgeNodeStatus = ({ node }) => (
  <div className="flex items-center justify-between p-3 bg-dark-800/30 rounded-lg">
    <div className="flex items-center gap-3">
      <div className={`status-dot ${node.status}`} />
      <span className="text-dark-200">{node.name}</span>
    </div>
    <div className="flex items-center gap-4 text-xs font-mono">
      <span className="text-dark-400">负载: {node.load.toFixed(0)}%</span>
      <span className="text-cyber-400">拦截: {node.blocked.toLocaleString()}</span>
    </div>
  </div>
)

// 实时日志
const LogEntry = ({ log }) => (
  <div className="flex items-start gap-2 text-xs font-mono py-1 border-b border-dark-800">
    <span className="text-dark-500">{new Date(log.timestamp).toLocaleTimeString()}</span>
    <span className={`${log.type === 'blocked' ? 'text-cyber-400' : 'text-danger-400'}`}>
      [{log.type === 'blocked' ? 'BLOCKED' : 'ALERT'}]
    </span>
    <span className="text-dark-300 flex-1 truncate">{log.message}</span>
  </div>
)

// 简化的世界地图
const WorldMap = ({ attackSources }) => (
  <div className="relative w-full h-48 bg-dark-800/50 rounded-lg overflow-hidden">
    {/* 简化的地图背景 */}
    <svg viewBox="0 0 1000 500" className="w-full h-full opacity-30">
      <path
        d="M150,100 Q200,80 250,100 L300,120 Q350,100 400,110 L450,90 Q500,100 550,95 L600,110 Q650,90 700,100 L750,80 Q800,100 850,90"
        fill="none"
        stroke="#22c55e"
        strokeWidth="1"
      />
      <ellipse cx="500" cy="250" rx="400" ry="200" fill="none" stroke="#22c55e" strokeWidth="0.5" strokeDasharray="5,5" />
    </svg>

    {/* 攻击来源点 */}
    {attackSources.map((source, index) => (
      <div
        key={source.country}
        className="map-marker bg-danger-500"
        style={{
          left: `${((source.lng + 180) / 360) * 100}%`,
          top: `${((90 - source.lat) / 180) * 100}%`,
          animationDelay: `${index * 0.2}s`,
        }}
        title={`${source.country}: ${source.count} 次攻击`}
      />
    ))}

    {/* 雷达扫描效果 */}
    <div className="absolute inset-0 flex items-center justify-center">
      <div className="w-32 h-32 rounded-full border border-cyber-500/20 relative">
        <div className="radar-sweep" />
      </div>
    </div>
  </div>
)

export default function DashboardPage() {
  const {
    threats,
    stats,
    edgeNodes,
    attackSources,
    logs,
    addThreat,
    updateStats,
    setEdgeNodes,
    setAttackSources,
    addLog,
  } = useThreatStore()

  const [chartData, setChartData] = useState([])
  const [currentTime, setCurrentTime] = useState(new Date())

  // 初始化数据
  useEffect(() => {
    // 初始化边缘节点
    setEdgeNodes(generateMockEdgeNodes())
    setAttackSources(generateMockAttackSources())

    // 初始化统计
    updateStats({
      totalThreats: 125847,
      blockedThreats: 124392,
      activeAttacks: 23,
      protectedRequests: 8547621,
    })

    // 初始化图表数据
    const initialChartData = Array.from({ length: 20 }, (_, i) => ({
      time: `${i}:00`,
      threats: Math.floor(Math.random() * 100) + 20,
      blocked: Math.floor(Math.random() * 80) + 15,
    }))
    setChartData(initialChartData)
  }, [])

  // 模拟实时威胁
  useEffect(() => {
    const threatInterval = setInterval(() => {
      const newThreat = generateMockThreat()
      addThreat(newThreat)

      // 添加日志
      addLog({
        type: newThreat.blocked ? 'blocked' : 'alert',
        message: `${THREAT_TYPES[newThreat.type]?.name} from ${newThreat.sourceIp} → ${newThreat.targetPath}`,
      })

      // 更新统计
      if (newThreat.blocked) {
        updateStats({ blockedThreats: stats.blockedThreats + 1 })
      }
    }, 3000)

    return () => clearInterval(threatInterval)
  }, [stats])

  // 更新时间
  useEffect(() => {
    const timeInterval = setInterval(() => {
      setCurrentTime(new Date())
    }, 1000)
    return () => clearInterval(timeInterval)
  }, [])

  // 更新图表数据
  useEffect(() => {
    const chartInterval = setInterval(() => {
      setChartData((prev) => {
        const newData = [...prev.slice(1), {
          time: new Date().toLocaleTimeString(),
          threats: Math.floor(Math.random() * 100) + 20,
          blocked: Math.floor(Math.random() * 80) + 15,
        }]
        return newData
      })
    }, 5000)
    return () => clearInterval(chartInterval)
  }, [])

  return (
    <div className="min-h-screen bg-dark-950 grid-bg">
      {/* 顶部导航 */}
      <header className="border-b border-dark-800 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <img src="/favicon.svg" alt="EdgeGuard" className="w-10 h-10" />
            <div>
              <h1 className="text-xl font-bold text-dark-100">EdgeGuard</h1>
              <p className="text-xs text-dark-500">全球威胁情报中心</p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            {/* 系统状态 */}
            <div className="flex items-center gap-2">
              <div className="status-dot online" />
              <span className="text-sm text-dark-300">系统正常</span>
            </div>

            {/* 当前时间 */}
            <div className="font-mono text-cyber-400">
              {currentTime.toLocaleString()}
            </div>

            {/* ESA 标识 */}
            <div className="text-xs text-dark-500">
              Powered by 阿里云 ESA
            </div>
          </div>
        </div>
      </header>

      {/* 主内容 */}
      <main className="max-w-[1800px] mx-auto px-6 py-6">
        {/* 统计卡片 */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCard
            title="总威胁数"
            value={stats.totalThreats}
            icon={Icons.Alert}
            trend={12}
          />
          <StatCard
            title="已拦截"
            value={stats.blockedThreats}
            icon={Icons.Ban}
            color="cyber"
          />
          <StatCard
            title="活跃攻击"
            value={stats.activeAttacks}
            icon={Icons.Activity}
            color="danger"
          />
          <StatCard
            title="受保护请求"
            value={stats.protectedRequests}
            icon={Icons.Shield}
          />
        </div>

        {/* 主要内容区 */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* 左侧 - 威胁趋势图 */}
          <div className="lg:col-span-2 space-y-6">
            {/* 趋势图 */}
            <div className="data-card p-5">
              <h2 className="text-lg font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <Icons.Activity />
                威胁趋势
              </h2>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3}/>
                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" stroke="#475569" fontSize={10} />
                    <YAxis stroke="#475569" fontSize={10} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1e293b',
                        border: '1px solid #334155',
                        borderRadius: '8px',
                      }}
                    />
                    <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" />
                    <Area type="monotone" dataKey="blocked" stroke="#22c55e" fill="url(#blockedGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* 全球攻击地图 */}
            <div className="data-card p-5">
              <h2 className="text-lg font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <Icons.Globe />
                全球攻击来源
              </h2>
              <WorldMap attackSources={attackSources} />
              <div className="mt-4 grid grid-cols-3 gap-2">
                {attackSources.slice(0, 6).map((source) => (
                  <div key={source.country} className="flex items-center justify-between p-2 bg-dark-800/30 rounded">
                    <span className="text-dark-300">{source.country}</span>
                    <span className="text-danger-400 font-mono text-sm">{source.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 右侧 - 实时威胁和节点状态 */}
          <div className="space-y-6">
            {/* 实时威胁 */}
            <div className="data-card p-5">
              <h2 className="text-lg font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <Icons.Alert />
                实时威胁
                <span className="ml-auto text-xs text-dark-500 font-mono">
                  {threats.length} 条记录
                </span>
              </h2>
              <div className="space-y-2 max-h-80 overflow-y-auto log-scroll">
                <AnimatePresence>
                  {threats.slice(0, 10).map((threat) => (
                    <ThreatItem key={threat.id} threat={threat} />
                  ))}
                </AnimatePresence>
              </div>
            </div>

            {/* 边缘节点状态 */}
            <div className="data-card p-5">
              <h2 className="text-lg font-semibold text-dark-100 mb-4 flex items-center gap-2">
                <Icons.Server />
                边缘节点状态
              </h2>
              <div className="space-y-2">
                {edgeNodes.map((node) => (
                  <EdgeNodeStatus key={node.id} node={node} />
                ))}
              </div>
            </div>

            {/* 实时日志 */}
            <div className="data-card p-5">
              <h2 className="text-lg font-semibold text-dark-100 mb-4">
                实时日志
              </h2>
              <div className="h-40 overflow-y-auto log-scroll">
                {logs.map((log) => (
                  <LogEntry key={log.id} log={log} />
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* 页脚 */}
      <footer className="border-t border-dark-800 mt-8">
        <div className="max-w-[1800px] mx-auto px-6 py-4 flex items-center justify-between text-xs text-dark-500">
          <div>EdgeGuard - 全球威胁情报中心</div>
          <div>
            本项目由
            <a href="https://www.aliyun.com/product/esa" target="_blank" rel="noopener noreferrer" className="text-cyber-500 hover:text-cyber-400 mx-1">
              阿里云 ESA
            </a>
            提供加速、计算和保护
          </div>
        </div>
      </footer>
    </div>
  )
}
