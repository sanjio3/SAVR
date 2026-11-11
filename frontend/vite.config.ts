import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

// 侧边栏底部显示真实版本号：直接从 package.json 读，不写死常量。
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8")) as { version: string };

export default defineConfig({
  plugins: [vue()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    // Vite 默认 extensions 顺序是 [.mjs, .js, .mts, .ts, …] —— .js 在 .ts **之前**，
    // 于是无扩展名导入（如 import router from "./router"）会优先解析到 .js。
    // 本项目历史上在 src 下留过一批 `tsc` 产物（.js 与 .ts 同名并存），
    // 那批 .js 是过期快照，导致「改了 .ts 但运行时跑的是旧 .js」的静默漂移：
    // 实测 router/index.js 仍带着已废弃的 `:tab?` 段，而 router/index.ts 早已去掉。
    // 那批过期产物已清理。
    // 这里显式把 .ts 提前，作为「将来若再冒出同名 .js 也不会抢走解析」的护栏 —— 源码真相只有 .ts。
    extensions: [".mjs", ".ts", ".tsx", ".js", ".jsx", ".json"],
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    host: true,
    port: 5200,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      // 前端的重连就会在代理上不断留下 ECONNRESET，而 http-proxy 默认把它打到 stdout，
      // 实测把 stack-frontend.log 刷到 2.4 万行 / 1.7MB —— 日志被噪音淹没后，
      // 真正的前端报错反而看不见了。这里只做「静默 + 节流计数」，不改变任何转发行为。
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true,
        configure: (proxy: any) => {
          let suppressed = 0;
          proxy.on("error", (_err: unknown, _req: unknown, res: any) => {
            suppressed += 1;
            // 每 50 条汇总一次，便于判断后端是真挂了还是偶发断连
            if (suppressed === 1 || suppressed % 50 === 0) {
              console.log(`[vite] /ws 代理已抑制 ${suppressed} 次上游连接错误（后端 8000 不可达？）`);
            }
            if (res && typeof res.writeHead === "function") {
              try {
                res.writeHead(502);
                res.end();
              } catch {
                /* 连接已断，无需回包 */
              }
            }
          });
        },
      },
    },
  },
});
