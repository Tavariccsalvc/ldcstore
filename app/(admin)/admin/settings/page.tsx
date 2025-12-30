import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Settings, Globe, CreditCard, CheckCircle, XCircle } from "lucide-react";

export default function SettingsPage() {
  // 从环境变量读取配置
  const siteName = process.env.NEXT_PUBLIC_SITE_NAME || "LDC Store";
  const siteDescription = process.env.NEXT_PUBLIC_SITE_DESCRIPTION || "未配置";
  
  // 检查支付配置
  const ldcPid = process.env.LDC_PID;
  const ldcSecret = process.env.LDC_SECRET;
  const isPaymentConfigured = !!(ldcPid && ldcSecret);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50">
          系统设置
        </h1>
        <p className="text-zinc-600 dark:text-zinc-400">
          查看当前系统配置状态
        </p>
      </div>

      <div className="grid gap-6">
        {/* Site Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Globe className="h-5 w-5" />
              网站配置
            </CardTitle>
            <CardDescription>
              通过环境变量配置，修改后需重启服务
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">网站名称</p>
                <p className="font-medium">{siteName}</p>
                <p className="text-xs text-muted-foreground">
                  环境变量: NEXT_PUBLIC_SITE_NAME
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">网站描述</p>
                <p className="font-medium">{siteDescription}</p>
                <p className="text-xs text-muted-foreground">
                  环境变量: NEXT_PUBLIC_SITE_DESCRIPTION
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Payment Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CreditCard className="h-5 w-5" />
              支付配置
            </CardTitle>
            <CardDescription>
              Linux DO Credit 支付状态
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3">
              {isPaymentConfigured ? (
                <>
                  <CheckCircle className="h-5 w-5 text-emerald-500" />
                  <span className="font-medium text-emerald-600 dark:text-emerald-400">
                    支付已配置
                  </span>
                  <Badge variant="secondary">LDC 支付可用</Badge>
                </>
              ) : (
                <>
                  <XCircle className="h-5 w-5 text-rose-500" />
                  <span className="font-medium text-rose-600 dark:text-rose-400">
                    支付未配置
                  </span>
                </>
              )}
            </div>
            
            <div className="rounded-lg border bg-muted/50 p-4">
              <p className="text-sm font-medium mb-2">配置说明</p>
              <p className="text-sm text-muted-foreground mb-3">
                在 .env 文件中添加以下环境变量：
              </p>
              <pre className="text-xs bg-zinc-900 text-zinc-100 p-3 rounded-md overflow-x-auto">
{`# Linux DO Credit 支付配置
LDC_PID=your_merchant_pid
LDC_SECRET=your_merchant_secret

# 可选：自定义支付网关
LDC_GATEWAY=https://credit.linux.do/epay`}
              </pre>
            </div>
          </CardContent>
        </Card>

        {/* Configuration Guide */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Settings className="h-5 w-5" />
              完整配置参考
            </CardTitle>
            <CardDescription>
              所有可用的环境变量配置
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-lg border bg-muted/50 p-4">
              <pre className="text-xs bg-zinc-900 text-zinc-100 p-3 rounded-md overflow-x-auto">
{`# 数据库
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# NextAuth 认证密钥
AUTH_SECRET=your_auth_secret

# 管理员后台密码
ADMIN_PASSWORD=your_admin_password

# Linux DO OAuth 登录（可选，用于用户登录）
LINUXDO_CLIENT_ID=your_oauth_client_id
LINUXDO_CLIENT_SECRET=your_oauth_client_secret

# 网站信息
NEXT_PUBLIC_SITE_NAME=LDC Store
NEXT_PUBLIC_SITE_DESCRIPTION=自动发卡系统

# Linux DO Credit 支付
LDC_PID=your_merchant_pid
LDC_SECRET=your_merchant_secret
LDC_GATEWAY=https://credit.linux.do/epay`}
              </pre>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
