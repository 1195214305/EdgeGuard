# EdgeGuard - 全球威胁情报中心

<div align="center">

![EdgeGuard Logo](frontend/public/favicon.svg)

**实时监控，智能防护，全球威胁一目了然**

本项目由[阿里云ESA](https://www.aliyun.com/product/esa)提供加速、计算和保护

![Aliyun ESA](https://img.alicdn.com/imgextra/i3/O1CN01H1UU3i1Cti9lYtFrs_!!6000000000139-2-tps-7534-844.png)

[![Powered by Aliyun ESA](https://img.shields.io/badge/Powered%20by-Aliyun%20ESA%20Pages-FF6A00?style=for-the-badge&logo=alibabacloud)](https://www.aliyun.com/product/esa)
[![Security](https://img.shields.io/badge/Security-Edge%20Protection-22c55e?style=for-the-badge)](https://www.aliyun.com/product/esa)
[![React](https://img.shields.io/badge/React-18.2-61DAFB?style=for-the-badge&logo=react)](https://react.dev/)

[在线体验](#在线体验) | [功能特性](#功能特性) | [技术架构](#技术架构) | [边缘计算应用](#边缘计算应用-how-we-use-edge)

#阿里云ESA Pages #阿里云云工开物

</div>

---

## 项目简介

**EdgeGuard** 是一款基于阿里云 ESA Pages 边缘计算平台构建的全球网络威胁实时情报大屏。它展示了边缘安全防护的强大能力，通过可视化的方式呈现全球网络攻击态势、威胁类型分布、边缘节点状态等关键安全指标。

### 核心亮点

- 🛡️ **实时威胁监控** - 毫秒级威胁检测和拦截，实时展示攻击态势
- 🌍 **全球攻击地图** - 可视化展示全球攻击来源分布
- ⚡ **边缘安全防护** - 在边缘侧实现 SQL 注入、XSS、DDoS 等攻击检测
- 📊 **数据可视化** - 专业的安全监控大屏设计，深色主题
- 🔄 **实时更新** - 威胁数据实时刷新，日志流式展示

---

## 功能演示

### 主仪表盘
![仪表盘](screenshots/dashboard.png)
*深色主题安全监控大屏，实时展示威胁态势*

### 威胁趋势图
![趋势图](screenshots/trends.png)
*威胁数量和拦截率实时趋势*

### 全球攻击地图
![攻击地图](screenshots/map.png)
*全球攻击来源可视化*

---

## 功能特性

### 监控功能

| 功能 | 描述 |
|------|------|
| 📈 **实时统计** | 总威胁数、已拦截、活跃攻击、受保护请求 |
| 🗺️ **攻击地图** | 全球攻击来源地理分布可视化 |
| 📊 **趋势图表** | 威胁数量和拦截率实时趋势 |
| 📋 **威胁列表** | 实时威胁事件列表，支持分类筛选 |
| 🖥️ **节点状态** | 全球边缘节点健康状态监控 |
| 📝 **实时日志** | 安全事件日志流式展示 |

### 威胁检测

| 威胁类型 | 检测方式 |
|----------|----------|
| 🔥 DDoS 攻击 | 流量异常检测、频率限制 |
| 💉 SQL 注入 | 正则规则匹配、语义分析 |
| 📜 XSS 攻击 | 脚本标签检测、编码分析 |
| 🔓 暴力破解 | 登录频率限制、IP 封禁 |
| 🦠 恶意软件 | User-Agent 分析、行为检测 |
| 🎣 钓鱼攻击 | URL 特征分析 |
| 🤖 恶意爬虫 | Bot 特征识别 |
| 🔍 漏洞扫描 | 扫描器指纹识别 |

---

## 技术架构

### 整体架构图

```
┌──────────────────────────────────────────────────────────────────┐
│                          用户浏览器                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  React 18 + Vite + TailwindCSS + Recharts                 │  │
│  │  ├── 深色主题安全监控 UI                                    │  │
│  │  ├── 实时数据可视化                                        │  │
│  │  └── Zustand 状态管理                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                      阿里云 ESA Pages                             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   边缘安全防护层                             │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │              威胁检测引擎 (Edge Functions)            │  │  │
│  │  │  - SQL 注入检测                                       │  │  │
│  │  │  - XSS 攻击检测                                       │  │  │
│  │  │  - 路径遍历检测                                       │  │  │
│  │  │  - 扫描器识别                                         │  │  │
│  │  │  - 频率限制                                           │  │  │
│  │  │  - IP 黑名单                                          │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    边缘函数 (Edge Functions)                │  │
│  │  ├── /api/threat/analyze  - 威胁分析                       │  │
│  │  ├── /api/threat/stats    - 统计数据                       │  │
│  │  ├── /api/edge/nodes      - 节点状态                       │  │
│  │  └── /api/edge/info       - 边缘信息                       │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    边缘存储 (Edge KV)                       │  │
│  │  ├── threat:rules         - 威胁规则库                     │  │
│  │  ├── blacklist:ips        - IP 黑名单                      │  │
│  │  └── stats:*              - 统计数据                       │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 边缘计算应用 (How We Use Edge)

EdgeGuard 深度利用阿里云 ESA 的边缘安全能力：

### 1. 边缘侧威胁检测

```javascript
// functions/threat/analyze.js
export async function onRequest(context) {
  const { request } = context;

  // 在边缘侧进行威胁检测
  const threats = [];

  // SQL 注入检测
  const sqlPatterns = [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
  ];

  for (const pattern of sqlPatterns) {
    if (pattern.test(request.url)) {
      threats.push({ type: 'SQL_INJECTION', level: 'CRITICAL' });
      break;
    }
  }

  // 如果检测到威胁，直接在边缘拦截
  if (threats.length > 0) {
    return new Response('Access Denied', { status: 403 });
  }
}
```

**优势**：
- 威胁在边缘侧直接拦截，不会到达源站
- 毫秒级响应，保护后端服务
- 减少源站负载

### 2. Geo-IP 攻击来源分析

```javascript
// 获取攻击者地理位置
const geoInfo = {
  country: request.headers.get('x-geo-country'),
  city: request.headers.get('x-geo-city'),
  latitude: request.headers.get('x-geo-latitude'),
  longitude: request.headers.get('x-geo-longitude'),
};

// 根据地理位置进行风险评估
const riskScore = calculateGeoRisk(geoInfo);
```

**应用场景**：
- 全球攻击来源可视化
- 基于地理位置的风险评估
- 区域性攻击趋势分析

### 3. 边缘频率限制

```javascript
// 边缘侧实现频率限制
const rateLimitMap = new Map();
const RATE_LIMIT = 100; // 每分钟最大请求数

const rateKey = `${clientIP}:${Math.floor(Date.now() / 60000)}`;
const currentRate = (rateLimitMap.get(rateKey) || 0) + 1;

if (currentRate > RATE_LIMIT) {
  return new Response('Rate Limited', { status: 429 });
}
```

### 4. 边缘规则库缓存

```javascript
// 威胁规则库存储在边缘 KV
// 全球边缘节点共享，实时更新

const rules = await env.THREAT_KV.get('rules:sql_injection', 'json');
```

---

## 项目结构

```
11_EdgeGuard_实时威胁情报/
├── frontend/                      # 前端代码
│   ├── src/
│   │   ├── pages/                # 页面
│   │   │   ├── DashboardPage.jsx # 主仪表盘
│   │   │   └── ThreatDetailPage.jsx # 威胁详情
│   │   ├── store/                # 状态管理
│   │   │   └── index.js          # Zustand Store
│   │   ├── App.jsx               # 应用入口
│   │   ├── main.jsx              # 渲染入口
│   │   └── index.css             # 全局样式（深色主题）
│   ├── public/                   # 静态资源
│   │   └── favicon.svg           # 盾牌图标
│   ├── index.html                # HTML 模板
│   ├── package.json              # 依赖配置
│   ├── vite.config.js            # Vite 配置
│   ├── tailwind.config.js        # Tailwind 配置
│   └── postcss.config.js         # PostCSS 配置
├── functions/                     # 边缘函数
│   └── threat/
│       └── analyze.js            # 威胁分析
├── screenshots/                   # 截图
└── README.md                      # 项目文档
```

---

## 快速开始

### 本地开发

```bash
# 1. 进入前端目录
cd frontend

# 2. 安装依赖
npm install

# 3. 启动开发服务器
npm run dev

# 4. 访问 http://localhost:5192
```

### 生产部署

1. 在阿里云 ESA 控制台创建 Pages 项目
2. 关联 GitHub 仓库
3. 配置构建命令：
   - 构建命令：`npm install && npm run build`
   - 根目录：`/frontend`
   - 输出目录：`dist`
4. 部署完成后，ESA 会自动在全球边缘节点同步

---

## 技术栈

| 类别 | 技术 |
|------|------|
| **前端框架** | React 18 + Vite |
| **样式方案** | TailwindCSS 3 (深色主题) |
| **动画库** | Framer Motion |
| **图表库** | Recharts |
| **状态管理** | Zustand |
| **路由** | React Router 6 |
| **部署平台** | 阿里云 ESA Pages |
| **边缘计算** | ESA Edge Functions |

---

## 设计理念

### 安全监控大屏风格

1. **深色主题**：减少视觉疲劳，突出数据
2. **绿色主色调**：代表安全、正常状态
3. **红色警告**：突出威胁和异常
4. **等宽字体**：技术数据更易读
5. **发光效果**：增强科技感

---

## 应用场景

1. **安全运维中心** - 实时监控网络安全态势
2. **企业安全展示** - 展示安全防护能力
3. **安全培训** - 演示常见攻击类型
4. **ESA 能力展示** - 展示边缘安全防护能力

---

## 许可证

MIT License

---

<div align="center">

**EdgeGuard** - 守护网络安全

Made with ❤️ for 阿里云 ESA Pages 边缘开发大赛

</div>
