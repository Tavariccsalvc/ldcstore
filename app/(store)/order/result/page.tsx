"use client";

import { useEffect, useState, useTransition, use } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { queryOrder } from "@/lib/actions/orders";
import { toast } from "sonner";
import {
  CheckCircle2,
  Clock,
  Loader2,
  Home,
  Copy,
  Package,
  XCircle,
} from "lucide-react";

interface OrderResultPageProps {
  searchParams: Promise<{ out_trade_no?: string }>;
}

interface OrderData {
  orderNo: string;
  productName: string;
  quantity: number;
  totalAmount: string;
  status: string;
  createdAt: Date;
  paidAt: Date | null;
  cards: string[];
}

export default function OrderResultPage({ searchParams }: OrderResultPageProps) {
  const params = use(searchParams);
  const orderNo = params.out_trade_no || "";

  const [isPending, startTransition] = useTransition();
  const [order, setOrder] = useState<OrderData | null>(null);
  const [password, setPassword] = useState("");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [error, setError] = useState("");

  const handleQuery = () => {
    if (!password) {
      setError("请输入查询密码");
      return;
    }
    setError("");

    startTransition(async () => {
      const result = await queryOrder(orderNo, password);
      if (result.success && result.data) {
        const data = Array.isArray(result.data) ? result.data[0] : result.data;
        setOrder(data as OrderData);
      } else {
        toast.error(result.message || "查询失败");
      }
    });
  };

  const copyToClipboard = async (text: string, index: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      toast.success("已复制");
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch {
      toast.error("复制失败");
    }
  };

  if (!orderNo) {
    return (
      <div className="mx-auto max-w-md px-4 py-12 text-center">
        <p className="text-muted-foreground">订单号无效</p>
        <Link href="/">
          <Button className="mt-4">返回首页</Button>
        </Link>
      </div>
    );
  }

  // 未查询状态 - 显示密码输入
  if (!order) {
    return (
      <div className="mx-auto max-w-md px-4 py-12">
        <Card>
          <CardContent className="pt-6 space-y-6">
            <div className="text-center">
              <CheckCircle2 className="mx-auto h-12 w-12 text-green-500" />
              <h1 className="mt-4 text-xl font-semibold">支付完成</h1>
              <p className="mt-2 text-sm text-muted-foreground">
                输入查询密码查看订单详情和卡密
              </p>
            </div>

            <div className="rounded-lg bg-muted/50 p-3 text-center">
              <p className="text-xs text-muted-foreground">订单号</p>
              <p className="font-mono font-medium">{orderNo}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">查询密码</Label>
              <Input
                id="password"
                type="password"
                placeholder="下单时设置的密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleQuery()}
              />
              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <Button
              className="w-full"
              onClick={handleQuery}
              disabled={isPending}
            >
              {isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  查询中
                </>
              ) : (
                "查看订单"
              )}
            </Button>

            <div className="text-center">
              <Link
                href="/"
                className="text-sm text-muted-foreground hover:text-foreground"
              >
                返回首页
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // 已查询 - 显示订单详情
  const isPaid = order.status === "paid" || order.status === "completed";

  return (
    <div className="mx-auto max-w-md px-4 py-12">
      <Card>
        <CardContent className="pt-6 space-y-6">
          {/* Status */}
          <div className="text-center">
            {isPaid ? (
              <CheckCircle2 className="mx-auto h-12 w-12 text-green-500" />
            ) : order.status === "pending" ? (
              <Clock className="mx-auto h-12 w-12 text-amber-500" />
            ) : (
              <XCircle className="mx-auto h-12 w-12 text-muted-foreground" />
            )}
            <h1 className="mt-4 text-xl font-semibold">{order.productName}</h1>
            <Badge
              variant={isPaid ? "default" : "secondary"}
              className="mt-2"
            >
              {order.status === "pending" && "待支付"}
              {order.status === "paid" && "已支付"}
              {order.status === "completed" && "已完成"}
              {order.status === "expired" && "已过期"}
              {order.status === "refunded" && "已退款"}
            </Badge>
          </div>

          {/* Order Info */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">订单号</span>
              <p className="font-mono">{order.orderNo}</p>
            </div>
            <div>
              <span className="text-muted-foreground">金额</span>
              <p className="font-semibold">¥{order.totalAmount}</p>
            </div>
            <div>
              <span className="text-muted-foreground">数量</span>
              <p>{order.quantity} 件</p>
            </div>
            <div>
              <span className="text-muted-foreground">下单时间</span>
              <p>{new Date(order.createdAt).toLocaleString("zh-CN")}</p>
            </div>
          </div>

          {/* Cards */}
          {order.cards && order.cards.length > 0 && (
            <div className="rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-900 dark:bg-green-950">
              <div className="mb-3 flex items-center gap-2 text-sm font-medium text-green-700 dark:text-green-300">
                <Package className="h-4 w-4" />
                卡密信息 ({order.cards.length} 个)
              </div>
              <div className="space-y-2">
                {order.cards.map((card, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between gap-2 rounded bg-white p-2 dark:bg-zinc-900"
                  >
                    <code className="text-sm font-mono break-all flex-1">
                      {card}
                    </code>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 shrink-0"
                      onClick={() => copyToClipboard(card, index)}
                    >
                      {copiedIndex === index ? (
                        <CheckCircle2 className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Pending Notice */}
          {order.status === "pending" && (
            <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-700 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300">
              <Clock className="inline h-4 w-4 mr-1" />
              订单待支付，请尽快完成支付
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3">
            <Link href="/order/query" className="flex-1">
              <Button variant="outline" className="w-full">
                查询其他订单
              </Button>
            </Link>
            <Link href="/" className="flex-1">
              <Button variant="ghost" className="w-full">
                <Home className="mr-2 h-4 w-4" />
                首页
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
