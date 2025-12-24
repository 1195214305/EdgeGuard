/**
 * EdgeGuard - 实时威胁情报平台
 * 主入口 Edge Function
 */

// 威胁规则库
const THREAT_RULES = {
  SQL_INJECTION: [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /((\%27)|(\'))union/i,
  ],
  XSS: [
    /((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/i,
    /javascript:/i,
    /on\w+\s*=/i,
  ],
  PATH_TRAVERSAL: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e%2f/i,
  ],
  SCANNER: [
    /nikto/i,
    /sqlmap/i,
    /nmap/i,
    /masscan/i,
  ],
}

// 恶意 IP 黑名单
const BLACKLISTED_IPS = new Set(['192.168.1.100', '10.0.0.50'])

// 请求频率限制
const rateLimitMap = new Map()
const RATE_LIMIT = 100

// CORS 头
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

// 主请求处理
async function handleRequest(request, env) {
  const url = new URL(request.url)
  const path = url.pathname

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  // API 路由
  if (path === '/api/threat/analyze' || path === '/api/threat/analyze/') {
    return handleThreatAnalyze(request)
  }

  if (path === '/api/edge/info' || path === '/api/edge/info/') {
    return handleEdgeInfo(request)
  }

  if (path === '/api/stats' || path === '/api/stats/') {
    return handleStats(request)
  }

  // 静态文件回退
  if (env && env.ASSETS) {
    return env.ASSETS.fetch(request)
  }

  return new Response(JSON.stringify({ error: 'Not found' }), {
    status: 404,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}

// 威胁分析
function handleThreatAnalyze(request) {
  const startTime = Date.now()
  const url = new URL(request.url)
  const clientIP = request.headers.get('x-real-ip') ||
                   request.headers.get('cf-connecting-ip') || 'unknown'
  const userAgent = request.headers.get('user-agent') || ''
  const path = url.pathname
  const query = url.search

  const threats = []

  // IP 黑名单检查
  if (BLACKLISTED_IPS.has(clientIP)) {
    threats.push({
      type: 'BLACKLISTED_IP',
      level: 'CRITICAL',
      message: `IP ${clientIP} 在黑名单中`,
    })
  }

  // 频率限制检查
  const rateKey = `${clientIP}:${Math.floor(Date.now() / 60000)}`
  const currentRate = (rateLimitMap.get(rateKey) || 0) + 1
  rateLimitMap.set(rateKey, currentRate)

  if (currentRate > RATE_LIMIT) {
    threats.push({
      type: 'RATE_LIMIT',
      level: 'HIGH',
      message: `IP ${clientIP} 超过频率限制`,
    })
  }

  // SQL 注入检测
  const fullUrl = path + query
  for (const pattern of THREAT_RULES.SQL_INJECTION) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'SQL_INJECTION',
        level: 'CRITICAL',
        message: '检测到 SQL 注入尝试',
      })
      break
    }
  }

  // XSS 检测
  for (const pattern of THREAT_RULES.XSS) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'XSS',
        level: 'HIGH',
        message: '检测到 XSS 攻击尝试',
      })
      break
    }
  }

  // 路径遍历检测
  for (const pattern of THREAT_RULES.PATH_TRAVERSAL) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'PATH_TRAVERSAL',
        level: 'HIGH',
        message: '检测到路径遍历尝试',
      })
      break
    }
  }

  // 扫描器检测
  for (const pattern of THREAT_RULES.SCANNER) {
    if (pattern.test(userAgent)) {
      threats.push({
        type: 'SCANNER',
        level: 'MEDIUM',
        message: '检测到扫描器',
      })
      break
    }
  }

  const response = {
    timestamp: new Date().toISOString(),
    clientIP,
    path,
    userAgent: userAgent.substring(0, 100),
    threats,
    blocked: threats.some(t => ['CRITICAL', 'HIGH'].includes(t.level)),
    processingTime: Date.now() - startTime,
    edgeNode: request.headers.get('x-edge-node') || 'unknown',
    geo: {
      country: request.headers.get('x-geo-country') || 'CN',
      city: request.headers.get('x-geo-city') || '',
    },
  }

  if (response.blocked) {
    return new Response(JSON.stringify({
      error: 'Access Denied',
      reason: 'Security threat detected',
      threats: threats.map(t => t.type),
    }), {
      status: 403,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
        'X-Threat-Detected': 'true',
      },
    })
  }

  return new Response(JSON.stringify(response), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'X-Edge-Security': 'passed',
    },
  })
}

// 边缘信息
function handleEdgeInfo(request) {
  const headers = request.headers
  const startTime = Date.now()

  return new Response(JSON.stringify({
    success: true,
    timestamp: startTime,
    geo: {
      ip: headers.get('x-real-ip') || 'unknown',
      country: headers.get('x-geo-country') || 'CN',
      city: headers.get('x-geo-city') || '',
      region: headers.get('x-geo-region') || '',
    },
    edgeNode: headers.get('x-edge-node') || 'CN-Shanghai',
    latency: Date.now() - startTime,
  }), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache',
    },
  })
}

// 统计信息
function handleStats(request) {
  return new Response(JSON.stringify({
    totalRequests: 12580,
    blockedRequests: 342,
    threatTypes: {
      SQL_INJECTION: 89,
      XSS: 156,
      PATH_TRAVERSAL: 45,
      SCANNER: 52,
    },
    topCountries: [
      { country: 'CN', count: 8500 },
      { country: 'US', count: 2100 },
      { country: 'RU', count: 980 },
    ],
    last24h: {
      requests: 1250,
      blocked: 34,
    },
  }), {
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
    },
  })
}

export default {
  fetch: handleRequest
}
