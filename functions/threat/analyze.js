/**
 * EdgeGuard - 威胁情报边缘函数
 * 路径: /api/threat/analyze
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
    /((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/i,
    /javascript:/i,
    /on\w+\s*=/i,
  ],
  PATH_TRAVERSAL: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e%2f/i,
    /%2e%2e\//i,
  ],
  SCANNER: [
    /nikto/i,
    /sqlmap/i,
    /nmap/i,
    /masscan/i,
    /dirbuster/i,
  ],
}

// 恶意 IP 黑名单
const BLACKLISTED_IPS = new Set([
  '192.168.1.100',
  '10.0.0.50',
])

// 请求频率限制
const rateLimitMap = new Map()
const RATE_LIMIT = 100

export default async function handler(request) {
  const startTime = Date.now()

  // CORS 处理
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
  }

  // 获取请求信息
  const url = new URL(request.url)
  const clientIP = request.headers.get('x-real-ip') ||
                   request.headers.get('cf-connecting-ip') ||
                   'unknown'
  const userAgent = request.headers.get('user-agent') || ''
  const path = url.pathname
  const query = url.search

  // 威胁检测结果
  const threats = []

  // 1. IP 黑名单检查
  if (BLACKLISTED_IPS.has(clientIP)) {
    threats.push({
      type: 'BLACKLISTED_IP',
      level: 'CRITICAL',
      message: `IP ${clientIP} 在黑名单中`,
    })
  }

  // 2. 频率限制检查
  const rateKey = `${clientIP}:${Math.floor(Date.now() / 60000)}`
  const currentRate = (rateLimitMap.get(rateKey) || 0) + 1
  rateLimitMap.set(rateKey, currentRate)

  if (currentRate > RATE_LIMIT) {
    threats.push({
      type: 'RATE_LIMIT',
      level: 'HIGH',
      message: `IP ${clientIP} 超过频率限制 (${currentRate}/${RATE_LIMIT})`,
    })
  }

  // 3. SQL 注入检测
  const fullUrl = path + query
  for (const pattern of THREAT_RULES.SQL_INJECTION) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'SQL_INJECTION',
        level: 'CRITICAL',
        message: `检测到 SQL 注入尝试: ${fullUrl.substring(0, 100)}`,
      })
      break
    }
  }

  // 4. XSS 检测
  for (const pattern of THREAT_RULES.XSS) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'XSS',
        level: 'HIGH',
        message: `检测到 XSS 攻击尝试`,
      })
      break
    }
  }

  // 5. 路径遍历检测
  for (const pattern of THREAT_RULES.PATH_TRAVERSAL) {
    if (pattern.test(fullUrl)) {
      threats.push({
        type: 'PATH_TRAVERSAL',
        level: 'HIGH',
        message: `检测到路径遍历尝试`,
      })
      break
    }
  }

  // 6. 扫描器检测
  for (const pattern of THREAT_RULES.SCANNER) {
    if (pattern.test(userAgent)) {
      threats.push({
        type: 'SCANNER',
        level: 'MEDIUM',
        message: `检测到扫描器: ${userAgent.substring(0, 50)}`,
      })
      break
    }
  }

  // 构建响应
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
      country: request.headers.get('x-geo-country'),
      city: request.headers.get('x-geo-city'),
    },
  }

  // 如果检测到严重威胁，返回 403
  if (response.blocked) {
    return new Response(JSON.stringify({
      error: 'Access Denied',
      reason: 'Security threat detected',
      threats: threats.map(t => t.type),
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'X-Threat-Detected': 'true',
        'X-Edge-Security': 'blocked',
      },
    })
  }

  return new Response(JSON.stringify(response), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Edge-Security': 'passed',
      'X-Processing-Time': `${response.processingTime}ms`,
    },
  })
}
