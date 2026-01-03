import Link from "next/link";
import { Github } from "lucide-react";

interface FooterProps {
  siteName?: string;
}

export function Footer({ siteName = "LDC Store" }: FooterProps) {
  return (
    <footer className="border-t border-border/50 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex flex-col items-center justify-center gap-1 py-4 max-w-3xl px-4 text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <span>© {new Date().getFullYear()} {siteName}</span>
          <span>🌟</span>
          <Link
            href="https://github.com/gptkong/ldc-store"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 hover:text-foreground transition-colors"
          >
            <Github className="h-3.5 w-3.5" />
            <span>GitHub</span>
          </Link>
        </div>
        <span className="text-xs text-muted-foreground/60">本站与 Linux DO 官方无任何关系</span>
      </div>
    </footer>
  );
}
