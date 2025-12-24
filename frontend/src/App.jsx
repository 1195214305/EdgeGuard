import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

// API 基础路径
const API_BASE = '/api'

// 威胁等级颜色
const LEVEL_COLORS = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
  SAFE: 'bg-green-500',
}

const LEVEL_TEXT = {
  CRITICAL: '严重',
  HIGH: '高危',
  MEDIUM: '中危',
  LOW: '低危',
  SAFE: '安全',
}

// 预设测试样例
const TEST_SAMPLES = [
  { name: 'SQL注入', payload: "' OR '1'='1' --", icon: '💉' },
  { name: 'XSS攻击', payload: '<script>alert("xss")</script>', icon: '📜' },
  { name: '路径遍历', payload: '../../../etc/passwd', icon: '📁' },
  { name: '命令注入', payload: '; cat /etc/passwd', icon: '⚡' },
  { name: 'Union注入', payload: "' UNION SELECT * FROM users --", icon: '🔗' },
  { name: '安全输入', payload: 'Hello World 你好世界', icon: '✅' },
]

export default function App() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [edgeInfo, setEdgeInfo] = useState(null)
  const [rules, setRules] = useState([])
  const [history, setHistory] = useState([])
  const [testResults, setTestResults] = useState(null)

  // 获取边缘信息
  useEffect(() => {
    fetch(`${API_BASE}/edge-info`)
      .then(res => res.json())
      .then(data => setEdgeInfo(data))
      .catch(console.error)

    fetch(`${API_BASE}/rules`)
      .then(res => res.json())
      .then(data => setRules(data.rules || []))
      .catch(console.error)
  }, [])

  // 分析输入
  const analyzeInput = async (payload = input) => {
    if (!payload.trim()) return

    setLoading(true)
    const startTime = Date.now()

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: payload }),
      })
      const data = await res.json()
      data.clientTime = Date.now() - startTime

      setResult(data)
      setHistory(prev => [
        { input: payload, result: data, time: new Date().toISOString() },
        ...prev.slice(0, 19),
      ])
    } catch (error) {
      setResult({ error: error.message })
    } finally {
      setLoading(false)
    }
  }

  // 运行所有测试
  const runAllTests = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/test-samples`)
      const data = await res.json()
      setTestResults(data)
    } catch (error) {
      console.error(error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* 头部 */}
      <header className="border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-green-400 to-cyan-500 rounded-lg flex items-center justify-center">
              <span className="text-xl">🛡️</span>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">EdgeGuard</h1>
              <p className="text-xs text-slate-400">边缘安全检测平台</p>
            </div>
          </div>

          {edgeInfo && (
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                <span className="text-slate-300">边缘节点: {edgeInfo.edge?.node || 'edge-cn'}</span>
              </div>
              <div className="text-slate-400">
                {edgeInfo.edge?.city || 'China'}, {edgeInfo.edge?.country || 'CN'}
              </div>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* 输入区域 */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50 mb-8"
        >
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <span>🔍</span> 安全检测
          </h2>

          <div className="flex gap-4 mb-4">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && analyzeInput()}
              placeholder="输入URL、参数或payload进行安全检测..."
              className="flex-1 bg-slate-900/50 border border-slate-600 rounded-xl px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
            />
            <button
              onClick={() => analyzeInput()}
              disabled={loading || !input.trim()}
              className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-green-500 text-white font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {loading ? '检测中...' : '检测'}
            </button>
          </div>

          {/* 快速测试按钮 */}
          <div className="flex flex-wrap gap-2">
            <span className="text-slate-400 text-sm py-1">快速测试:</span>
            {TEST_SAMPLES.map((sample) => (
              <button
                key={sample.name}
                onClick={() => {
                  setInput(sample.payload)
                  analyzeInput(sample.payload)
                }}
                className="px-3 py-1 bg-slate-700/50 hover:bg-slate-600/50 text-slate-300 text-sm rounded-lg transition-colors flex items-center gap-1"
              >
                <span>{sample.icon}</span>
                {sample.name}
              </button>
            ))}
            <button
              onClick={runAllTests}
              className="px-3 py-1 bg-purple-600/50 hover:bg-purple-500/50 text-purple-200 text-sm rounded-lg transition-colors ml-2"
            >
              🧪 运行全部测试
            </button>
          </div>
        </motion.div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* 检测结果 */}
          <div className="lg:col-span-2 space-y-6">
            <AnimatePresence mode="wait">
              {result && (
                <motion.div
                  key={result.input}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50"
                >
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-lg font-semibold text-white">检测结果</h3>
                    <div className={`px-4 py-1 rounded-full text-white text-sm font-medium ${LEVEL_COLORS[result.analysis?.riskLevel] || 'bg-slate-600'}`}>
                      {LEVEL_TEXT[result.analysis?.riskLevel] || '未知'}
                    </div>
                  </div>

                  {/* 风险评分 */}
                  <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-slate-400">风险评分</span>
                      <span className="text-2xl font-bold text-white">{result.analysis?.riskScore || 0}/100</span>
                    </div>
                    <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${result.analysis?.riskScore || 0}%` }}
                        className={`h-full ${
                          (result.analysis?.riskScore || 0) >= 60 ? 'bg-red-500' :
                          (result.analysis?.riskScore || 0) >= 40 ? 'bg-orange-500' :
                          (result.analysis?.riskScore || 0) >= 20 ? 'bg-yellow-500' :
                          (result.analysis?.riskScore || 0) > 0 ? 'bg-blue-500' : 'bg-green-500'
                        }`}
                      />
                    </div>
                  </div>

                  {/* 检测到的威胁 */}
                  {result.analysis?.threats?.length > 0 ? (
                    <div className="mb-6">
                      <h4 className="text-slate-300 mb-3">检测到的威胁 ({result.analysis.threats.length})</h4>
                      <div className="space-y-2">
                        {result.analysis.threats.map((threat, i) => (
                          <div key={i} className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-white font-medium">{threat.name}</span>
                              <span className={`px-2 py-0.5 rounded text-xs ${LEVEL_COLORS[threat.level]} text-white`}>
                                {LEVEL_TEXT[threat.level]}
                              </span>
                            </div>
                            <div className="text-slate-400 text-sm font-mono truncate">
                              匹配: {threat.matched}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="mb-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                      <div className="flex items-center gap-2 text-green-400">
                        <span>✅</span>
                        <span>未检测到安全威胁</span>
                      </div>
                    </div>
                  )}

                  {/* 性能信息 */}
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-slate-700/50">
                    <div>
                      <div className="text-slate-500 text-xs mb-1">边缘处理时间</div>
                      <div className="text-cyan-400 font-mono">{result.performance?.processingTime}</div>
                    </div>
                    <div>
                      <div className="text-slate-500 text-xs mb-1">总响应时间</div>
                      <div className="text-cyan-400 font-mono">{result.clientTime}ms</div>
                    </div>
                    <div>
                      <div className="text-slate-500 text-xs mb-1">处理节点</div>
                      <div className="text-cyan-400 font-mono">{result.edge?.node || 'edge'}</div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* 批量测试结果 */}
            {testResults && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50"
              >
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">🧪 批量测试结果</h3>
                  <span className="text-green-400 font-mono">{testResults.passRate} 通过</span>
                </div>
                <div className="space-y-2">
                  {testResults.samples?.map((sample, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className={sample.passed ? 'text-green-400' : 'text-red-400'}>
                          {sample.passed ? '✓' : '✗'}
                        </span>
                        <span className="text-white">{sample.name}</span>
                        <code className="text-slate-400 text-sm bg-slate-800 px-2 py-0.5 rounded max-w-xs truncate">
                          {sample.payload}
                        </code>
                      </div>
                      <div className="text-slate-400 text-sm">
                        {sample.detected ? `检测到: ${sample.threats.join(', ')}` : '安全'}
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* 检测历史 */}
            {history.length > 0 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50"
              >
                <h3 className="text-lg font-semibold text-white mb-4">📋 检测历史</h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {history.map((item, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between p-3 bg-slate-900/50 rounded-lg hover:bg-slate-900/70 cursor-pointer"
                      onClick={() => {
                        setInput(item.input)
                        setResult(item.result)
                      }}
                    >
                      <code className="text-slate-300 text-sm truncate max-w-md">
                        {item.input}
                      </code>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${LEVEL_COLORS[item.result.analysis?.riskLevel]} text-white`}>
                          {item.result.analysis?.riskScore || 0}分
                        </span>
                        <span className="text-slate-500 text-xs">
                          {new Date(item.time).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </div>

          {/* 右侧信息 */}
          <div className="space-y-6">
            {/* 边缘节点信息 */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50"
            >
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span>🌐</span> 边缘节点
              </h3>
              {edgeInfo ? (
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-slate-400">节点ID</span>
                    <span className="text-cyan-400 font-mono">{edgeInfo.edge?.node}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">位置</span>
                    <span className="text-white">{edgeInfo.edge?.city}, {edgeInfo.edge?.country}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">您的IP</span>
                    <span className="text-white font-mono">{edgeInfo.edge?.clientIp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">规则数量</span>
                    <span className="text-green-400">{edgeInfo.ruleCount} 类 / {edgeInfo.patternCount} 条</span>
                  </div>
                </div>
              ) : (
                <div className="text-slate-500">加载中...</div>
              )}
            </motion.div>

            {/* 检测规则 */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 }}
              className="bg-slate-800/50 rounded-2xl p-6 border border-slate-700/50"
            >
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span>📋</span> 检测规则
              </h3>
              <div className="space-y-2">
                {rules.map((rule) => (
                  <div key={rule.type} className="flex items-center justify-between p-2 bg-slate-900/50 rounded-lg">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${LEVEL_COLORS[rule.level]}`}></span>
                      <span className="text-slate-300 text-sm">{rule.name}</span>
                    </div>
                    <span className="text-slate-500 text-xs">{rule.patternCount} 条规则</span>
                  </div>
                ))}
              </div>
            </motion.div>

            {/* ESA 说明 */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className="bg-gradient-to-br from-cyan-500/10 to-green-500/10 rounded-2xl p-6 border border-cyan-500/30"
            >
              <h3 className="text-lg font-semibold text-white mb-3">⚡ ESA 边缘优势</h3>
              <ul className="space-y-2 text-slate-300 text-sm">
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>威胁检测在边缘节点完成，延迟 &lt;10ms</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>全球分布式部署，就近处理请求</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>恶意请求在边缘即被拦截，保护源站</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400">✓</span>
                  <span>无需部署服务器，Serverless 架构</span>
                </li>
              </ul>
            </motion.div>
          </div>
        </div>
      </main>

      {/* 页脚 */}
      <footer className="border-t border-slate-700/50 mt-16">
        <div className="max-w-7xl mx-auto px-4 py-6 flex items-center justify-between text-sm text-slate-500">
          <div>EdgeGuard - 边缘安全检测平台</div>
          <div>
            Powered by{' '}
            <a
              href="https://www.aliyun.com/product/esa"
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 hover:text-cyan-300"
            >
              阿里云 ESA
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}
