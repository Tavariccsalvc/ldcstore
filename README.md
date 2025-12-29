# LDC Store - 自动发卡系统

基于 Next.js 16 的虚拟商品自动发卡平台，支持 Linux DO Credit 积分支付。

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FYOUR_USERNAME%2Fldc-store&env=DATABASE_URL,AUTH_SECRET,LDC_PID,LDC_SECRET&envDescription=Required%20environment%20variables&envLink=https%3A%2F%2Fgithub.com%2FYOUR_USERNAME%2Fldc-store%23environment-variables&project-name=ldc-store&repository-name=ldc-store)

## ✨ 特性

- 🛒 **前台商店** - 商品展示、分类导航、搜索功能
- 🔐 **游客购买** - 无需注册，邮箱 + 查询密码即可下单
- 💳 **自动发卡** - 支付成功后自动发放卡密
- 📦 **库存管理** - 批量导入卡密、去重检测、库存预警
- 📊 **后台管理** - 商品/订单/分类/卡密全方位管理
- 🎨 **现代 UI** - 基于 Shadcn/UI，支持深色模式

## 🛠️ 技术栈

- **Framework:** Next.js 16 (App Router, Server Actions)
- **Language:** TypeScript
- **Database:** PostgreSQL (推荐 Neon/Supabase)
- **ORM:** Drizzle ORM
- **UI:** Shadcn/UI + Tailwind CSS
- **Auth:** NextAuth.js v5
- **Payment:** Linux DO Credit

## 🚀 一键部署到 Vercel

1. 点击上方 "Deploy with Vercel" 按钮
2. 在 Vercel 中配置环境变量
3. 等待部署完成
4. 运行数据库迁移初始化

## 📦 本地开发

### 1. 克隆项目

```bash
git clone https://github.com/YOUR_USERNAME/ldc-store.git
cd ldc-store
pnpm install
```

### 2. 配置环境变量

创建 `.env` 文件：

```env
# 数据库 (推荐 Neon: https://neon.tech)
DATABASE_URL="postgresql://user:password@host/database?sslmode=require"

# NextAuth 密钥 (生成: openssl rand -base64 32)
AUTH_SECRET="your-auth-secret"
AUTH_TRUST_HOST=true

# Linux DO Credit 支付
LDC_PID="your_client_id"
LDC_SECRET="your_client_secret"
LDC_GATEWAY="https://credit.linux.do/epay"

# 网站配置
NEXT_PUBLIC_SITE_URL="http://localhost:3000"
NEXT_PUBLIC_SITE_NAME="LDC Store"

# 订单过期时间（分钟）
ORDER_EXPIRE_MINUTES=30
```

### 3. 初始化数据库

```bash
# 推送表结构到数据库
pnpm db:push

# 初始化管理员账户和示例数据
pnpm db:seed
```

### 4. 启动开发服务器

```bash
pnpm dev
```

访问:
- 前台商店: http://localhost:3000
- 后台管理: http://localhost:3000/admin

### 默认管理员账户

| 邮箱 | 密码 |
|------|------|
| admin@example.com | admin123 |

## 🔧 环境变量说明

| 变量 | 必填 | 说明 |
|------|------|------|
| `DATABASE_URL` | ✅ | PostgreSQL 连接字符串 |
| `AUTH_SECRET` | ✅ | NextAuth 加密密钥 |
| `LDC_PID` | ⚠️ | Linux DO Credit Client ID |
| `LDC_SECRET` | ⚠️ | Linux DO Credit Secret |
| `LDC_GATEWAY` | ❌ | 支付网关地址（默认官方地址）|
| `NEXT_PUBLIC_SITE_URL` | ❌ | 网站地址 |
| `NEXT_PUBLIC_SITE_NAME` | ❌ | 网站名称 |
| `ORDER_EXPIRE_MINUTES` | ❌ | 订单过期时间（默认30分钟）|

## 📝 Linux DO Credit 配置

1. 访问 [Linux DO Credit 控制台](https://credit.linux.do)
2. 创建新应用，获取 `pid` 和 `key`
3. 配置回调地址:
   - **Notify URL:** `https://your-domain.com/api/payment/notify`
   - **Return URL:** `https://your-domain.com/order/result`

## 📁 项目结构

```
ldc-store/
├── app/
│   ├── (store)/          # 前台商店
│   ├── (admin)/          # 后台管理
│   └── api/              # API 路由
├── components/
│   ├── ui/               # Shadcn UI
│   ├── store/            # 前台组件
│   └── admin/            # 后台组件
├── lib/
│   ├── db/               # 数据库配置
│   ├── actions/          # Server Actions
│   ├── payment/          # 支付集成
│   └── validations/      # Zod 验证
└── ...
```

## 🗃️ 数据库命令

```bash
# 生成迁移文件
pnpm db:generate

# 推送表结构（开发环境）
pnpm db:push

# 运行迁移（生产环境）
pnpm db:migrate

# 打开数据库可视化工具
pnpm db:studio

# 初始化种子数据
pnpm db:seed

# 重置数据库（危险！）
pnpm db:reset
```

## 📄 License

MIT
