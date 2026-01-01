"use server";

import { signIn } from "@/lib/auth";
import { headers } from "next/headers";
import { z } from "zod";
import {
  checkRateLimit,
  recordFailedAttempt,
  clearRateLimit,
  getClientIP,
} from "@/lib/rate-limit";

const loginSchema = z.object({
  password: z.string().min(1, "请输入密码"),
});

export interface LoginResult {
  success: boolean;
  message: string;
  remaining?: number;
  blocked?: boolean;
}

/**
 * 管理员密码登录（带速率限制）
 */
export async function adminLogin(password: string): Promise<LoginResult> {
  // 获取客户端 IP
  const headersList = await headers();
  const clientIP = getClientIP(headersList);

  // 检查速率限制
  const rateLimit = checkRateLimit(clientIP);
  if (!rateLimit.success) {
    return {
      success: false,
      message: rateLimit.message || "请求过于频繁，请稍后再试",
      remaining: rateLimit.remaining,
      blocked: rateLimit.blocked,
    };
  }

  // 验证输入
  const parsed = loginSchema.safeParse({ password });
  if (!parsed.success) {
    return {
      success: false,
      message: parsed.error.issues[0].message,
    };
  }

  try {
    // 尝试登录
    const result = await signIn("credentials", {
      password: parsed.data.password,
      redirect: false,
    });

    // signIn 成功时不会返回 error
    if (result?.error) {
      // 登录失败，记录失败尝试
      const failResult = recordFailedAttempt(clientIP);
      
      let message = "密码错误";
      if (failResult.blocked) {
        message = failResult.message || "登录尝试次数过多，请稍后再试";
      } else if (failResult.remaining !== undefined && failResult.remaining <= 2) {
        message = `密码错误，还剩 ${failResult.remaining} 次尝试机会`;
      }

      return {
        success: false,
        message,
        remaining: failResult.remaining,
        blocked: failResult.blocked,
      };
    }

    // 登录成功，清除速率限制记录
    clearRateLimit(clientIP);

    return {
      success: true,
      message: "登录成功",
    };
  } catch (error) {
    // NextAuth 登录失败会抛出错误
    const failResult = recordFailedAttempt(clientIP);

    let message = "密码错误";
    if (failResult.blocked) {
      message = failResult.message || "登录尝试次数过多，请稍后再试";
    } else if (failResult.remaining !== undefined && failResult.remaining <= 2) {
      message = `密码错误，还剩 ${failResult.remaining} 次尝试机会`;
    }

    // 检查是否是凭证错误
    if (error instanceof Error && error.message.includes("CredentialsSignin")) {
      return {
        success: false,
        message,
        remaining: failResult.remaining,
        blocked: failResult.blocked,
      };
    }

    console.error("登录错误:", error);
    return {
      success: false,
      message: "登录失败，请稍后再试",
    };
  }
}

