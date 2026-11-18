# NanoLimbo_Private — Telegram WebProxy 部署指南

本项目在 NanoLimbo limbo 服务器中内置了 Telegram MTProto WebProxy（移植自 eooce/Telegram-webproxy 的 nodejs 实现），与 limbo 服务同进程启动。

## 一、必须关注的文件（部署/移植核心）

新增的 Telegram WebProxy 模块，全部位于
`src/main/java/ua/nanit/limbo/telegram/`：

| 文件 | 作用 | 部署必要性 |
|---|---|---|
| `TgCrypto.java` | 协议核心：secret 归一化、boot/session token、fakeTLS head 构建、AES-CTR 流、MTProto 包解析 | 必需 |
| `TgWebProxyServer.java` | Netty HTTP+WS 监听、Lease 会话限额（4096）、升级握手 | 必需 |
| `TgHttpHandler.java` | 路由：`/health`、`/api/v1/session`（POST/DELETE）、WS 升级入口 | 必需 |
| `TgLaneHandler.java` | WS lane：解析 `tproxy-lane-v1.TOKEN.SID` 子协议、鉴权、挂接 TgSession | 必需 |
| `TgSession.java` | 单会话桥接：客户端 ↔ Telegram DC（wss://kws{dc}.web.telegram.org/apiws） | 必需 |

被修改的原有文件（升级到新版本时需保留这些改动）：

| 文件 | 改动内容 |
|---|---|
| `src/main/java/ua/nanit/limbo/NanoLimbo.java` | ① `ALL_ENV_VARS` 增加 `TG_PORT` / `TG_SECRET` / `TG_DOMAIN`；② 新增 `startTelegramProxy(envVars)`，在 `LimboServer.start()` 前启动代理；③ 日志重定向改为 `.tglog` 文件（Java 8 兼容） |

构建配置（无需改动，但部署编译依赖）：

- `build.gradle` / `settings.gradle` / `gradlew` / `gradle/` — Gradle 8 + shadow 打包，`gradlew shadowJar` 产物即部署 jar。

## 二、可以不上传的内容

- `build/`、`.gradle/`、`tmpnh/` — 本地构建产物与缓存。
- `testsrc/`（TgSelfTest / HttpSmoke / wsclient.js / SrvBg*.java）、`srv.log`、`cli.log` — 本地测试脚手架，可留在本地，不影响部署。
- `.tglog`（运行时生成）。

## 三、环境变量（部署配置）

| 变量 | 默认 | 说明 |
|---|---|---|
| `TG_PORT` | `3000` | WebProxy HTTP/WS 监听端口 |
| `TG_SECRET` | 复用 `UUID` env | 32 hex 或 UUID；也接受 `dd`/`ee`/`ef` + 32hex 前缀形式 |
| `TG_DOMAIN` | 自动取公网 IP | 对外展示域名，用于生成 t.me 链接 |

启动后日志会输出订阅链接：`https://t.me/webproxy?server=<TG_DOMAIN>&secret=<TG_SECRET>`，可直接在 Telegram 客户端添加代理。

## 四、构建与部署步骤

```bash
# 1. 构建 fat jar（Java 8+）
./gradlew shadowJar
# 产物: build/libs/NanoLimbo-<version>-all.jar

# 2. 运行（与 limbo 同进程）
TG_PORT=3000 TG_SECRET=<32hex或UUID> TG_DOMAIN=your.domain java -jar NanoLimbo-<version>-all.jar
```

本地无 Gradle 网络环境时可用 javac 直接编译（依赖从 gradle 缓存取）：

```bash
CP=$(find ~/.gradle/caches/modules-2/files-2.1 -name "*.jar" | grep -v -E "sources|javadoc" | tr '\n' ';')
javac -encoding UTF-8 -source 8 -target 8 -cp "$CP" -d build/classes $(find src/main/java -name "*.java")
```

注意：`BuildConfig.LIMBO_VERSION` 由 Gradle buildconfig 插件生成；javac 直编时需提供 stub。

## 五、协议兼容性（已验证）

与 eooce/Telegram-webproxy（nodejs/index.js）完全对齐：
- 帧格式 `type(1B)+sid(3B BE)+len(4B BE)`；type 1=open / 2=data / 3=end / 0x11=welcome
- token：`body(4B exp BE + 12B nonce) + HMAC(boot, kind+"\n"+body)[0..16]`，base64url 43 字符
- bootstrap token 2 分钟 / session token 5 分钟有效期
- fakeTLS 64B head，dc = ±(target+1)，负数为 media
- 上游 `wss://kws{dc+1}[-1].web.telegram.org/apiws`，subprotocol `binary`
- 流控 4MB window / 64KB 下行分片

测试状态：crypto 单元 23 项、HTTP 冒烟 8 项、WS 端到端全部通过。
