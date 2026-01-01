/**
 * 简易速率限制器
 * 用于防止暴力破解攻击
 * 
 * 注意：此实现使用内存存储，不适合多实例部署
 * 生产环境建议使用 @upstash/ratelimit + Redis
 */

interface RateLimitRecord {
  count: number;
  firstAttempt: number;
  lastAttempt: number;
  blocked: boolean;
  blockedUntil: number;
}

// 存储登录尝试记录
const loginAttempts = new Map<string, RateLimitRecord>();

// 配置
const CONFIG = {
  // 时间窗口（毫秒）- 15分钟
  WINDOW_MS: 15 * 60 * 1000,
  // 最大尝试次数
  MAX_ATTEMPTS: 5,
  // 封禁时间（毫秒）- 30分钟
  BLOCK_DURATION_MS: 30 * 60 * 1000,
  // 清理间隔（毫秒）- 5分钟
  CLEANUP_INTERVAL_MS: 5 * 60 * 1000,
};

// 定期清理过期记录
let cleanupInterval: NodeJS.Timeout | null = null;

function startCleanup() {
  if (cleanupInterval) return;
  
  cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of loginAttempts.entries()) {
      // 如果被封禁且封禁时间已过，或者记录已过期，则删除
      if (record.blocked && record.blockedUntil < now) {
        loginAttempts.delete(key);
      } else if (!record.blocked && now - record.firstAttempt > CONFIG.WINDOW_MS) {
        loginAttempts.delete(key);
      }
    }
  }, CONFIG.CLEANUP_INTERVAL_MS);
}

// 启动清理任务
startCleanup();

export interface RateLimitResult {
  success: boolean;
  remaining: number;
  resetIn: number; // 秒
  blocked: boolean;
  message?: string;
}

/**
 * 检查是否允许登录尝试
 * @param identifier 标识符（通常是 IP 地址）
 */
export function checkRateLimit(identifier: string): RateLimitResult {
  const now = Date.now();
  let record = loginAttempts.get(identifier);

  // 如果被封禁
  if (record?.blocked) {
    if (record.blockedUntil > now) {
      const resetIn = Math.ceil((record.blockedUntil - now) / 1000);
      return {
        success: false,
        remaining: 0,
        resetIn,
        blocked: true,
        message: `登录尝试次数过多，请 ${Math.ceil(resetIn / 60)} 分钟后再试`,
      };
    }
    // 封禁已过期，清除记录
    loginAttempts.delete(identifier);
    record = undefined;
  }

  // 如果没有记录或记录已过期，创建新记录
  if (!record || now - record.firstAttempt > CONFIG.WINDOW_MS) {
    return {
      success: true,
      remaining: CONFIG.MAX_ATTEMPTS,
      resetIn: Math.ceil(CONFIG.WINDOW_MS / 1000),
      blocked: false,
    };
  }

  // 检查剩余尝试次数
  const remaining = CONFIG.MAX_ATTEMPTS - record.count;
  if (remaining <= 0) {
    return {
      success: false,
      remaining: 0,
      resetIn: Math.ceil((record.firstAttempt + CONFIG.WINDOW_MS - now) / 1000),
      blocked: false,
      message: `尝试次数过多，请稍后再试`,
    };
  }

  return {
    success: true,
    remaining,
    resetIn: Math.ceil((record.firstAttempt + CONFIG.WINDOW_MS - now) / 1000),
    blocked: false,
  };
}

/**
 * 记录登录失败
 * @param identifier 标识符（通常是 IP 地址）
 */
export function recordFailedAttempt(identifier: string): RateLimitResult {
  const now = Date.now();
  let record = loginAttempts.get(identifier);

  // 如果被封禁且未过期
  if (record?.blocked && record.blockedUntil > now) {
    const resetIn = Math.ceil((record.blockedUntil - now) / 1000);
    return {
      success: false,
      remaining: 0,
      resetIn,
      blocked: true,
      message: `登录尝试次数过多，请 ${Math.ceil(resetIn / 60)} 分钟后再试`,
    };
  }

  // 如果没有记录或记录已过期，创建新记录
  if (!record || now - record.firstAttempt > CONFIG.WINDOW_MS) {
    record = {
      count: 1,
      firstAttempt: now,
      lastAttempt: now,
      blocked: false,
      blockedUntil: 0,
    };
    loginAttempts.set(identifier, record);
    
    return {
      success: true,
      remaining: CONFIG.MAX_ATTEMPTS - 1,
      resetIn: Math.ceil(CONFIG.WINDOW_MS / 1000),
      blocked: false,
    };
  }

  // 增加失败次数
  record.count += 1;
  record.lastAttempt = now;

  // 检查是否需要封禁
  if (record.count >= CONFIG.MAX_ATTEMPTS) {
    record.blocked = true;
    record.blockedUntil = now + CONFIG.BLOCK_DURATION_MS;
    loginAttempts.set(identifier, record);

    const resetIn = Math.ceil(CONFIG.BLOCK_DURATION_MS / 1000);
    return {
      success: false,
      remaining: 0,
      resetIn,
      blocked: true,
      message: `登录尝试次数过多，账户已被临时锁定 ${Math.ceil(resetIn / 60)} 分钟`,
    };
  }

  loginAttempts.set(identifier, record);
  const remaining = CONFIG.MAX_ATTEMPTS - record.count;

  return {
    success: true,
    remaining,
    resetIn: Math.ceil((record.firstAttempt + CONFIG.WINDOW_MS - now) / 1000),
    blocked: false,
    message: remaining <= 2 ? `还剩 ${remaining} 次尝试机会` : undefined,
  };
}

/**
 * 登录成功后清除记录
 * @param identifier 标识符
 */
export function clearRateLimit(identifier: string): void {
  loginAttempts.delete(identifier);
}

/**
 * 获取客户端 IP（适用于 Next.js）
 * @param headers 请求头
 */
export function getClientIP(headers: Headers): string {
  // Cloudflare
  const cfConnectingIP = headers.get("cf-connecting-ip");
  if (cfConnectingIP) return cfConnectingIP;

  // Vercel / 通用代理
  const xForwardedFor = headers.get("x-forwarded-for");
  if (xForwardedFor) {
    // 取第一个 IP（最原始的客户端 IP）
    return xForwardedFor.split(",")[0].trim();
  }

  // X-Real-IP
  const xRealIP = headers.get("x-real-ip");
  if (xRealIP) return xRealIP;

  // 默认
  return "unknown";
}

