/**
 * EdgeGuard - 边缘安全网关
 * 主入口函数 - 处理所有API请求
 *
 * 核心功能：
 * 1. 实时威胁检测 - SQL注入、XSS、路径遍历等
 * 2. 请求分析 - 分析任意URL/payload的安全性
 * 3. 边缘信息 - 展示ESA边缘节点信息
 */

// ==================== 威胁检测规则库 ====================

const THREAT_RULES = {
  SQL_INJECTION: {
    name: 'SQL注入',
    level: 'CRITICAL',
    patterns: [
      /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
      /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
      /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
      /((\%27)|(\'))union/i,
      /union[\s\S]*select/i,
      /select[\s\S]*from/i,
      /insert[\s\S]*into/i,
      /drop[\s\S]*table/i,
      /delete[\s\S]*from/i,
      /update[\s\S]*set/i,
      /exec(\s|\+)+(s|x)p\w+/i,
    ],
  },
  XSS: {
    name: 'XSS攻击',
    level: 'HIGH',
    patterns: [
      /<script[\s\S]*?>[\s\S]*?<\/script>/i,
      /<img[^>]+onerror\s*=/i,
      /<[^>]+on\w+\s*=/i,
      /javascript:/i,
      /vbscript:/i,
      /expression\s*\(/i,
      /<iframe[\s\S]*?>/i,
      /<object[\s\S]*?>/i,
      /<embed[\s\S]*?>/i,
      /<svg[\s\S]*?onload/i,
    ],
  },
  PATH_TRAVERSAL: {
    name: '路径遍历',
    level: 'HIGH',
    patterns: [
      /\.\.\//g,
      /\.\.\\/g,
      /%2e%2e%2f/i,
      /%2e%2e\//i,
      /\.\.%2f/i,
      /%252e%252e%252f/i,
      /etc\/passwd/i,
      /etc\/shadow/i,
      /windows\/system32/i,
    ],
  },
  COMMAND_INJECTION: {
    name: '命令注入',
    level: 'CRITICAL',
    patterns: [
      /;\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat)/i,
      /\|\s*(ls|cat|rm|wget|curl|bash|sh|nc|netcat)/i,
      /`[^`]*`/,
      /\$\([^)]*\)/,
      /&&\s*(ls|cat|rm|wget|curl)/i,
      /\|\|\s*(ls|cat|rm|wget|curl)/i,
    ],
  },
  SCANNER: {
    name: '扫描器探测',
    level: 'MEDIUM',
    patterns: [
      /nikto/i,
      /sqlmap/i,
      /nmap/i,
      /masscan/i,
      /dirbuster/i,
      /gobuster/i,
      /wpscan/i,
      /acunetix/i,
      /nessus/i,
      /burpsuite/i,
    ],
  },
  SENSITIVE_FILE: {
    name: '敏感文件访问',
    level: 'MEDIUM',
    patterns: [
      /\.env$/i,
      /\.git\//i,
      /\.svn\//i,
      /\.htaccess/i,
      /web\.config/i,
      /wp-config\.php/i,
      /config\.php/i,
      /database\.yml/i,
      /\.aws\/credentials/i,
      /id_rsa/i,
    ],
  },
}

// ==================== 核心检测函数 ====================

function detectThreats(input, userAgent = '') {
  const threats = []
  const inputLower = input.toLowerCase()

  for (const [type, rule] of Object.entries(THREAT_RULES)) {
    for (const pattern of rule.patterns) {
      if (pattern.test(input) || pattern.test(inputLower)) {
        threats.push({
          type,
          name: rule.name,
          level: rule.level,
          pattern: pattern.toString(),
          matched: input.match(pattern)?.[0] || 'detected',
        })
        break // 每种类型只报告一次
      }
    }
  }

  // 检测User-Agent中的扫描器特征
  if (userAgent) {
    for (const pattern of THREAT_RULES.SCANNER.patterns) {
      if (pattern.test(userAgent)) {
        threats.push({
          type: 'SCANNER',
          name: '扫描器探测',
          level: 'MEDIUM',
          pattern: pattern.toString(),
          matched: userAgent.match(pattern)?.[0] || 'detected',
        })
        break
      }
    }
  }

  return threats
}

// 计算风险评分 (0-100)
function calculateRiskScore(threats) {
  if (threats.length === 0) return 0

  const levelScores = {
    CRITICAL: 40,
    HIGH: 25,
    MEDIUM: 15,
    LOW: 5,
  }

  let score = 0
  for (const threat of threats) {
    score += levelScores[threat.level] || 10
  }

  return Math.min(100, score)
}

// ==================== API 路由处理 ====================

export default async function handler(request, context) {
  const url = new URL(request.url)
  const path = url.pathname

  // CORS 头
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }

  // 处理 OPTIONS 预检请求
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  // 获取边缘节点信息
  const edgeInfo = {
    node: request.headers.get('x-edge-node') || context?.geo?.datacenter || 'edge-cn',
    country: request.headers.get('x-geo-country') || context?.geo?.country || 'CN',
    city: request.headers.get('x-geo-city') || context?.geo?.city || 'Unknown',
    clientIp: request.headers.get('x-real-ip') ||
              request.headers.get('cf-connecting-ip') ||
              request.headers.get('x-forwarded-for')?.split(',')[0] ||
              'unknown',
    timestamp: new Date().toISOString(),
  }

  try {
    // ========== API: 分析请求/payload ==========
    if (path === '/api/analyze' || path === '/api/threat/analyze') {
      const startTime = Date.now()

      let inputToAnalyze = ''
      let userAgent = request.headers.get('user-agent') || ''

      if (request.method === 'POST') {
        const body = await request.json().catch(() => ({}))
        inputToAnalyze = body.input || body.url || body.payload || ''
        userAgent = body.userAgent || userAgent
      } else {
        inputToAnalyze = url.searchParams.get('input') ||
                         url.searchParams.get('url') ||
                         url.searchParams.get('q') ||
                         url.search
      }

      const threats = detectThreats(inputToAnalyze, userAgent)
      const riskScore = calculateRiskScore(threats)
      const processingTime = Date.now() - startTime

      const result = {
        success: true,
        input: inputToAnalyze.substring(0, 500), // 限制返回长度
        analysis: {
          threatCount: threats.length,
          threats,
          riskScore,
          riskLevel: riskScore >= 60 ? 'CRITICAL' :
                     riskScore >= 40 ? 'HIGH' :
                     riskScore >= 20 ? 'MEDIUM' :
                     riskScore > 0 ? 'LOW' : 'SAFE',
          blocked: riskScore >= 40,
        },
        edge: edgeInfo,
        performance: {
          processingTime: `${processingTime}ms`,
          analyzedAt: new Date().toISOString(),
        },
      }

      return new Response(JSON.stringify(result, null, 2), {
        status: result.analysis.blocked ? 403 : 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'X-Edge-Node': edgeInfo.node,
          'X-Risk-Score': riskScore.toString(),
          'X-Processing-Time': `${processingTime}ms`,
        },
      })
    }

    // ========== API: 获取边缘节点信息 ==========
    if (path === '/api/edge-info') {
      return new Response(JSON.stringify({
        success: true,
        edge: edgeInfo,
        capabilities: [
          '实时威胁检测',
          'SQL注入防护',
          'XSS攻击防护',
          '路径遍历防护',
          '命令注入防护',
          '扫描器识别',
          '敏感文件保护',
        ],
        ruleCount: Object.keys(THREAT_RULES).length,
        patternCount: Object.values(THREAT_RULES).reduce((sum, r) => sum + r.patterns.length, 0),
      }, null, 2), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      })
    }

    // ========== API: 获取检测规则列表 ==========
    if (path === '/api/rules') {
      const rules = Object.entries(THREAT_RULES).map(([type, rule]) => ({
        type,
        name: rule.name,
        level: rule.level,
        patternCount: rule.patterns.length,
      }))

      return new Response(JSON.stringify({
        success: true,
        rules,
        totalPatterns: rules.reduce((sum, r) => sum + r.patternCount, 0),
      }, null, 2), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      })
    }

    // ========== API: 批量测试示例 ==========
    if (path === '/api/test-samples') {
      const samples = [
        { name: 'SQL注入', payload: "' OR '1'='1' --", expected: 'SQL_INJECTION' },
        { name: 'XSS攻击', payload: '<script>alert("xss")</script>', expected: 'XSS' },
        { name: '路径遍历', payload: '../../../etc/passwd', expected: 'PATH_TRAVERSAL' },
        { name: '命令注入', payload: '; cat /etc/passwd', expected: 'COMMAND_INJECTION' },
        { name: '敏感文件', payload: '/.git/config', expected: 'SENSITIVE_FILE' },
        { name: '安全输入', payload: 'hello world', expected: 'SAFE' },
      ]

      const results = samples.map(sample => {
        const threats = detectThreats(sample.payload)
        return {
          ...sample,
          detected: threats.length > 0,
          threats: threats.map(t => t.type),
          passed: threats.length > 0 ? threats.some(t => t.type === sample.expected) : sample.expected === 'SAFE',
        }
      })

      return new Response(JSON.stringify({
        success: true,
        samples: results,
        passRate: `${results.filter(r => r.passed).length}/${results.length}`,
        edge: edgeInfo,
      }, null, 2), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      })
    }

    // ========== API: 健康检查 ==========
    if (path === '/api/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        service: 'EdgeGuard',
        version: '2.0.0',
        edge: edgeInfo,
        uptime: Date.now(),
      }, null, 2), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      })
    }

    // ========== 默认: 404 ==========
    return new Response(JSON.stringify({
      error: 'Not Found',
      availableEndpoints: [
        'POST /api/analyze - 分析输入内容的安全性',
        'GET /api/edge-info - 获取边缘节点信息',
        'GET /api/rules - 获取检测规则列表',
        'GET /api/test-samples - 运行测试样例',
        'GET /api/health - 健康检查',
      ],
    }, null, 2), {
      status: 404,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
      },
    })

  } catch (error) {
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: error.message,
    }), {
      status: 500,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json',
      },
    })
  }
}
