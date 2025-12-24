import { create } from 'zustand'

// 威胁类型
export const THREAT_TYPES = {
  DDOS: { name: 'DDoS 攻击', color: '#ef4444', icon: '🔥' },
  SQL_INJECTION: { name: 'SQL 注入', color: '#f97316', icon: '💉' },
  XSS: { name: 'XSS 攻击', color: '#eab308', icon: '📜' },
  BRUTE_FORCE: { name: '暴力破解', color: '#a855f7', icon: '🔓' },
  MALWARE: { name: '恶意软件', color: '#ec4899', icon: '🦠' },
  PHISHING: { name: '钓鱼攻击', color: '#06b6d4', icon: '🎣' },
  BOT: { name: '恶意爬虫', color: '#8b5cf6', icon: '🤖' },
  SCANNER: { name: '漏洞扫描', color: '#64748b', icon: '🔍' },
}

// 威胁等级
export const THREAT_LEVELS = {
  CRITICAL: { name: '严重', color: '#ef4444', priority: 4 },
  HIGH: { name: '高危', color: '#f97316', priority: 3 },
  MEDIUM: { name: '中危', color: '#eab308', priority: 2 },
  LOW: { name: '低危', color: '#22c55e', priority: 1 },
}

// 主状态管理
export const useThreatStore = create((set, get) => ({
  // 威胁列表
  threats: [],

  // 实时统计
  stats: {
    totalThreats: 0,
    blockedThreats: 0,
    activeAttacks: 0,
    protectedRequests: 0,
  },

  // 边缘节点状态
  edgeNodes: [],

  // 攻击来源地图数据
  attackSources: [],

  // 实时日志
  logs: [],

  // 是否正在加载
  isLoading: false,

  // 边缘信息
  edgeInfo: null,

  // 设置威胁列表
  setThreats: (threats) => set({ threats }),

  // 添加新威胁
  addThreat: (threat) => set((state) => ({
    threats: [threat, ...state.threats].slice(0, 100),
    stats: {
      ...state.stats,
      totalThreats: state.stats.totalThreats + 1,
      activeAttacks: state.stats.activeAttacks + 1,
    },
  })),

  // 更新统计
  updateStats: (stats) => set((state) => ({
    stats: { ...state.stats, ...stats },
  })),

  // 设置边缘节点
  setEdgeNodes: (nodes) => set({ edgeNodes: nodes }),

  // 设置攻击来源
  setAttackSources: (sources) => set({ attackSources: sources }),

  // 添加日志
  addLog: (log) => set((state) => ({
    logs: [
      {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        ...log,
      },
      ...state.logs,
    ].slice(0, 50),
  })),

  // 设置加载状态
  setLoading: (isLoading) => set({ isLoading }),

  // 设置边缘信息
  setEdgeInfo: (info) => set({ edgeInfo: info }),

  // 清空日志
  clearLogs: () => set({ logs: [] }),
}))

// 模拟数据生成
export const generateMockThreat = () => {
  const types = Object.keys(THREAT_TYPES)
  const levels = Object.keys(THREAT_LEVELS)
  const countries = ['CN', 'US', 'RU', 'BR', 'IN', 'DE', 'FR', 'JP', 'KR', 'GB']
  const ips = [
    '192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.',
    '198.51.100.', '185.220.101.', '45.33.32.', '104.248.0.',
  ]

  const type = types[Math.floor(Math.random() * types.length)]
  const level = levels[Math.floor(Math.random() * levels.length)]
  const country = countries[Math.floor(Math.random() * countries.length)]
  const ip = ips[Math.floor(Math.random() * ips.length)] + Math.floor(Math.random() * 255)

  return {
    id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type,
    level,
    sourceIp: ip,
    sourceCountry: country,
    targetPath: ['/', '/api/login', '/admin', '/wp-admin', '/api/users'][Math.floor(Math.random() * 5)],
    timestamp: new Date().toISOString(),
    blocked: Math.random() > 0.2,
    details: {
      userAgent: 'Mozilla/5.0 (compatible; malicious-bot/1.0)',
      requestCount: Math.floor(Math.random() * 1000) + 1,
      payload: type === 'SQL_INJECTION' ? "' OR '1'='1" : null,
    },
  }
}

// 生成模拟边缘节点
export const generateMockEdgeNodes = () => [
  { id: 'cn-beijing', name: '北京', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 10000) },
  { id: 'cn-shanghai', name: '上海', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 10000) },
  { id: 'cn-shenzhen', name: '深圳', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 10000) },
  { id: 'cn-hangzhou', name: '杭州', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 10000) },
  { id: 'sg', name: '新加坡', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 5000) },
  { id: 'jp-tokyo', name: '东京', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 5000) },
  { id: 'us-west', name: '美西', status: 'warning', load: Math.random() * 100, blocked: Math.floor(Math.random() * 8000) },
  { id: 'eu-frankfurt', name: '法兰克福', status: 'online', load: Math.random() * 100, blocked: Math.floor(Math.random() * 6000) },
]

// 生成模拟攻击来源
export const generateMockAttackSources = () => [
  { country: 'CN', count: Math.floor(Math.random() * 5000), lat: 35.86, lng: 104.19 },
  { country: 'US', count: Math.floor(Math.random() * 8000), lat: 37.09, lng: -95.71 },
  { country: 'RU', count: Math.floor(Math.random() * 6000), lat: 61.52, lng: 105.31 },
  { country: 'BR', count: Math.floor(Math.random() * 3000), lat: -14.23, lng: -51.92 },
  { country: 'IN', count: Math.floor(Math.random() * 4000), lat: 20.59, lng: 78.96 },
  { country: 'DE', count: Math.floor(Math.random() * 2000), lat: 51.16, lng: 10.45 },
]
