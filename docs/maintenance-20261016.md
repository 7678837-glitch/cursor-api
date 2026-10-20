# 维护评估：2026-10-16

本次维护保留 Chat Completions、Responses 和单 Cursor 账号结构，更新官方 SDK、修复现有接口并加强运行边界。Anthropic / Claude Code 接口及多 Key 池按用户确认的范围暂缓接入。

## 依赖与官方接口

| 项目 | 原版本 | 当前版本 | 核验来源 |
| --- | --- | --- | --- |
| `@cursor/sdk` | 1.0.30 | 1.0.37 | [npm 官方包](https://www.npmjs.com/package/@cursor/sdk)，`npm view @cursor/sdk version engines dependencies` |
| TypeScript | 5.9.2 | 7.0.2 | [官方版本说明](https://github.com/microsoft/typescript-go/releases/tag/typescript%2Fv7.0.2)，`npm view typescript version` |
| `@types/node` | 22.18.12 | 22.20.5 | `npm view @types/node@22 version`；保留与最低支持 Node 22 相符的类型版本 |
| GitHub Actions | checkout/setup-node v4；Docker v3/v3/v5/v6 | checkout/setup-node v7；buildx/login v4；metadata v6；build-push v7 | 各官方仓库的 `releases/latest` 与 `action.yml` 输入定义 |

Node 最低版本继续是 **22.13**，Docker 继续使用 Node 22 和 `linux/amd64`。锁文件包含 SDK 与 TypeScript 所需的各平台可选包。新版 SDK 已不再依赖 `@connectrpc/connect-node` / `undici`，删除了旧的 `undici` 强制覆盖；`undici-types` 是 Node 类型声明依赖，仍然保留。`npm audit` 返回 0 个已知漏洞。

以 [Cursor TypeScript SDK 文档](https://cursor.com/docs/sdk/typescript)、[SDK 发布说明](https://prod.cursor.com/docs/release-notes/sdk)和安装包的 `.d.ts` 声明交叉核对：

- `Agent.create/resume`、`local.customTools`、`settingSources: []`、`tools: [] / ["mcp"]` 仍适用。恢复会话时继续显式传工具限制，避免开启内置 shell / 文件工具。
- 模型和参数从 `Cursor.models.list()` 获取；Responses 的 `reasoning.effort` 映射到目录支持的最近档位，无对应参数时忽略。显式的 `reasoning_effort` 继续严格校验。
- `RunResult.error` 的 `message/code` 用于失败诊断；SDK 的状态码、请求 ID、重试标记用于区分 409、429、503、504。
- 官方发布说明页面目前列到 1.0.35；**1.0.37 的存在与版本信息来自 npm 元数据**，不将未公开的发布细节当成已知事实。
- 官方 SDK 没有提供精确 tokenizer 或账号剩余额度接口；用量和费用继续以官方返回值为准。

## 未合并 PR 的评估与落地

这是本地代码评估和整合记录，GitHub PR 的合并状态需单独处理。

| PR | 评估 | 本次处理 |
| --- | --- | --- |
| [#15 Anthropic Messages](https://github.com/xjoker/cursor-api/pull/15) | 新增第三套协议；部分客户端选项被忽略或降级，需要独立定义兼容性契约 | 暂缓；与 #23 作为独立功能评估 |
| [#16 CI / 健康检查](https://github.com/xjoker/cursor-api/pull/16) | PR 校验和容器探针对维护有直接价值 | 已整合；探针读取实际 TOML / 环境变量地址、端口，无需双重配置 |
| [#17 Cursor Key 池](https://github.com/xjoker/cursor-api/pull/17) | 自动切换 Key 会改变账号和会话归属 | 暂缓；需验证跨账号模型目录、重启后 Key 归属和流式输出后禁止切换 |
| [#18 SSE 心跳](https://github.com/xjoker/cursor-api/pull/18) | 长时间无模型输出可能被代理断开 | 已整合：立即发送响应头、定时 SSE 注释、断连后停止计时器 |
| [#19 上游错误](https://github.com/xjoker/cursor-api/pull/19) | 统一 502 丢失可操作的故障分类 | 已整合：保留结构化诊断；包含 NetworkError 的 504 优先映射 |
| [#20 采样兼容](https://github.com/xjoker/cursor-api/pull/20) | 某些客户端固定发送不支持的采样参数 | 已整合，`ignore_sampling_params` 默认关闭；打开后仍拒绝不支持的输出格式 |
| [#21 无状态工具续接](https://github.com/xjoker/cursor-api/pull/21) | 网关生成的会话 ID 阻断按历史匹配，造成工具回合重放 | 已整合；显式客户端 ID 仍优先，客户端 Key 之间保持隔离 |
| [#22 reasoning 档位](https://github.com/xjoker/cursor-api/pull/22) | Responses 客户端的档位与各模型目录不完全一致 | 已整合；就近映射，等距取低档，显式严格参数不变 |
| [#23 Claude Code](https://github.com/xjoker/cursor-api/pull/23) | 包含 #15/#22，不可当成三个独立补丁重复应用；token 估算会影响上下文压缩 | 暂缓；若后续接入，精确计数不可用时默认关闭估算 |
| [#24 会话上限 / TTL](https://github.com/xjoker/cursor-api/pull/24) | 内存会话需要资源上限，持久化映射需要过期策略 | 已整合；并发创建前原子占位，只淘汰待回传工具的会话，全忙返回 503 |
| [#25 least_active](https://github.com/xjoker/cursor-api/pull/25) | 依赖 #17；HTTP 在途请求数量并不等于停车会话数量 | 暂缓；需真实长流和工具停车负载验证分布 |
| [#26 Key 池管理页](https://github.com/xjoker/cursor-api/pull/26) | 包含 #17/#25，需要先确认底层状态语义 | 随 Key 池暂缓，当前管理台不增加不存在的功能 |
| [#27 日志脱敏](https://github.com/xjoker/cursor-api/pull/27) | 原规则误遮 token 数，同时漏掉日志 message 中的秘密 | 已整合并补充嵌套对象、数组和数组字符串脱敏；保留计数、Key ID |
| [#28 认证加固](https://github.com/xjoker/cursor-api/pull/28) | 管理密钥猜测需要限流，管理页需要防嵌入 | 已整合：达到上限后在校验凭据前拒绝同地址请求，并返回 Retry-After；增加管理页安全响应头 |

已合并 PR 的结果保留，关闭的 [#7](https://github.com/xjoker/cursor-api/pull/7) 不重新纳入；图表时段不属于本次已确认修复。关闭的 issue [#1](https://github.com/xjoker/cursor-api/issues/1)、[#2](https://github.com/xjoker/cursor-api/issues/2)、[#3](https://github.com/xjoker/cursor-api/issues/3) 对应的取消、用量未知和 SQLite 日志容量行为继续由现有测试覆盖。

## 开放 issue

- [#29 count_tokens](https://github.com/xjoker/cursor-api/issues/29)：当前没有 Anthropic 接口，继续返回 404。SDK 无精确计数接口；后续不能将字符估算当成精确值，估算默认关闭。
- [#30 请求限流](https://github.com/xjoker/cursor-api/issues/30)：本次增加认证失败限制和全局会话上限；业务请求速率建议由反向代理控制，尚未增加按 Key 的配额系统。代理层应按部署负载设定阈值，参考 [nginx 限流文档](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)。SSE 应关闭代理缓冲，参考 [proxy_buffering](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering)。没有使用 nginx 运行验证。
- [#31 CORS](https://github.com/xjoker/cursor-api/issues/31)：已实现 `cors_allow_origins` / `CORS_ALLOW_ORIGINS`。默认直接返回 `*`，精确白名单仅回显匹配来源并加 `Vary: Origin`，空字符串完全关闭 CORS。预检、成功响应和错误响应使用同一策略。CORS 是浏览器访问策略，不替代客户端 Key 校验。
- [#32 真实上游验证](https://github.com/xjoker/cursor-api/issues/32)：仍未完成。官方 SDK 使用现有本机配置请求模型目录，返回 `401 Invalid User API Key`，因此没有进行真实模型、工具往返、费用和反向代理长流验证。

## 兼容性边界

默认启用每地址每分钟 20 次失败认证限制、15 秒 SSE 心跳、256 个运行或停车会话上限、30 天会话映射 TTL；严格采样参数校验仍为默认。会话映射过期与淘汰后，客户端需要发送完整历史才能重放上下文。

认证限制使用直连 socket 地址，不信任可伪造的 `X-Forwarded-For`。代理后面的客户端会共享限制，达到上限后包括合法密钥在内的请求会暂时被拒绝；这能防止攻击者在收到 429 后继续校验猜测。通过代理层限流和调整 `AUTH_FAILURE_LIMIT` 管理共享地址场景。

## 验证

- 修复前：先提取 PR 测试，定向执行 12 项测试结果为 1 通过、11 失败，含无状态工具回合实际重放、采样参数拒绝和待实现导出缺失。
- 边界修复前：CORS、嵌套数组字符串脱敏、同时创建会话的新增测试共复现 5 项失败；NetworkError 504 与认证限流必须在凭据检查前执行的测试分别复现失败。
- 初次收尾：`npm run typecheck` 通过；`npm test` **80 通过、0 失败**，包括真实临时 SQLite、HTTP、SSE、认证和 CORS 测试。模型行为使用模拟 SDK；上游错误类型测试导入真实 `@cursor/sdk`。
- 独立审查修复：新增或扩展的用例先复现 4 项失败；修复 response ID 持久化、404 CORS 和数据库写失败后的 Agent 释放后，受影响的 **11 项定向测试全部通过**，编译通过。SQLite 故障测试使用真实数据库的只读模式。
- `npm audit`：0 个已知漏洞。
- `docker build --platform=linux/amd64 --no-cache`：构建通过；一次性容器的 Docker 健康状态为 `healthy`，TOML 自定义端口 8899、`/health` 版本、官方 SDK 导入、管理页安全响应头及未认证请求 401 检查通过。测试容器已停止，临时配置已清理。
- GitHub Actions 的 Node 矩阵和远端工作流尚未运行；本地全量测试运行于 Node 24，容器运行于 Node 22。

版本由根 `VERSION` 统一为 `20261016.1`。生产环境生效情况不在上述本地测试的结论范围内。
