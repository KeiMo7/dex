# 刷新令牌宽限期、重放检测与令牌族撤销

日期：2026-11-22
状态：已实现

## 1. 问题

刷新令牌轮换（rotation）是「用过即废」：`Rotate` 把旧 secret 移到 `ObsoleteToken`
并签发新 secret。现有实现虽有一个 `reuseInterval` 雏形，但存在三个缺口：

1. **并发刷新互相踩死。** 宽限期内多个请求带着同一个旧令牌并发到达时，后到的请求
   直接拿到新令牌返回——客户端会拿到它从未见过的 refresh token 副本，且没有
   「只允许一次成功」的语义保证；默认配置（`reuseInterval=0`）下后到请求必然
   `invalid_grant`，用户被反复踢下线。
2. **没有重放检测与令牌族（token family）撤销。** 超出宽限期再使用旧 secret 时，
   只能拒绝这一个令牌；无法识别「令牌已泄露」并沿派生根撤销整族。
3. **族撤销不传播到访问令牌。** 访问令牌是自包含 JWT，没有任何撤销登记，族被判定
   泄露后，已签发的访问令牌在自然过期前始终有效。

## 2. 目标与约束

- 轮换后旧令牌在**可配置宽限期**内仍可用；超过宽限期即失效。默认宽限期为 0
  （保持现有一次性失效语义不变）。
- 同一旧令牌在宽限期内被并发使用时，**恰好一次成功**；其余请求返回可区分的
  「已被使用（grace period reuse）」错误，而不是笼统的「无效」。
- 超出宽限期的旧令牌使用 = **重放**：判定泄露，撤销整个令牌族，写安全审计日志。
- 族撤销沿**图**传播到该族全部刷新令牌与访问令牌。
- 并发去重基于**存储层原子操作**（CAS/行锁/etcd Txn），不依赖应用层分布式锁、
  不依赖时钟。
- 宽限期状态**持久化**：进程重启后，仍在宽限期内的旧令牌信息不丢。
- 存储不可用时**保守拒绝**刷新（fail-closed）；族失效信号丢失时，访问令牌按自身
  过期时间兜底。
- 复用现有签发/校验实现，不新增第三方依赖。

## 3. 数据模型：令牌族图

扁平表只存「当前行 + 一个 obsolete secret」，撤销时无法沿派生根遍历。新增两个
存储实体，构成邻接表形式的有向图（每个节点持有 `family_id` 与 `parent_id`，
族头节点可被一次标记整族失效，避免扁平关系漏节点）：

### 3.1 `TokenFamily`（族头，图的根）

| 字段 | 说明 |
|---|---|
| `ID` | 族 ID，首次签发 refresh token 时生成 |
| `ClientID` / `UserID` / `ConnectorID` | 审计与索引 |
| `CreatedAt` | 族创建时间 |
| `RevokedAt` | 零值表示存活；非零表示整族已撤销 |
| `RevokeReason` | `replay` / `admin` 等，审计依据 |
| `LastReplayedToken` | 触发撤销的令牌 ID，审计依据 |

族头一行承载「整族是否失效」信号：访问令牌校验只需一次点查，不必遍历图。

### 3.2 `TokenNode`（图节点）

| 字段 | 说明 |
|---|---|
| `ID` | 节点 ID（刷新节点 = refresh token 行 ID；访问节点 = JWT `jti`） |
| `FamilyID` | 所属族（边：node → family root） |
| `ParentID` | 派生来源节点 ID（边：node → parent），族头节点为空 |
| `Kind` | `refresh` / `access` |
| `ClientID` / `UserID` / `ConnectorID` | 审计 |
| `CreatedAt` | 节点创建时间 |
| `ExpiresAt` | 访问令牌的自然过期时间（GC 与兜底用） |
| `RevokedAt` | 零值存活；族撤销时逐节点标记 |

派生词条：refresh token `R0`（族头节点）→ 轮换出 `R1`（parent=R0）→ 再轮换
`R2`；每次刷新签发的访问令牌 `A1..An` 以对应 refresh 节点为 parent。族撤销时
`UpdateTokenFamily` 先原子标记族头，再列出该族全部节点标记 `RevokedAt`。

### 3.3 与现有 `RefreshToken` 行的关系

不改变现有轮换存储形态（`Token`/`ObsoleteToken`/`LastUsed` 保持不变，宽限期状态
随该行持久化，重启不丢），只在 `storage.RefreshToken` 上增加 `FamilyID` 与
`ObsoleteConsumedAt` 两个字段。

- **族在 `RefreshStore.Create` 时即建立**：每个新签发的刷新令牌都出生在自己的族里，
  图从第一次签发就完整，避免在刷新热路径上做惰性建图（那会在 claim 事务外引入额外
  存储写，破坏依赖固定调用次数的单连接后端与回滚计数）。
- **历史无族行（`FamilyID=""`）**：由升级前的版本或直接写库的测试创建。它们继续
  支持行级宽限期 CAS（`ObsoleteConsumedAt` 不依赖族），但不参与族级重放撤销——
  超窗口使用旧 secret 时保持历史的一次性 `invalid_grant` 语义且行不被删除。这保证
  默认配置（`reuseInterval=0`）下行为与旧版本逐字节一致。
- 重放分类（`ErrRefreshTokenReplayed`）只对 `FamilyID != ""` 的行生效；无族行走
  `ErrRefreshTokenClaimedTwice`，两者都映射为 `invalid_grant`，但只有前者撤销族。

### 3.4 访问令牌撤销登记

访问令牌签发时写一个 `kind=access` 的 TokenNode（`ID=jti`、`ExpiresAt=JWT exp`）。
introspection 在现有签名/过期/session 校验之后，增加一次族/节点状态点查：

- 族 `RevokedAt != 0` 或节点 `RevokedAt != 0` → `active=false`。
- 点查返回基础设施错误 → 返回 500（不静默放行）。
- 节点/族记录不存在（信号丢失、GC 已清理、族功能开启前的旧令牌）→ 按 JWT 自身
  过期时间兜底，即现有行为。

## 4. 刷新流程的状态机

对一次携带 secret `T` 的刷新请求，`LookupRefreshToken` + `Rotate` 的 claim 阶段
（单个存储原子事务内）按下列顺序判定：

1. 行不存在 / client 不匹配 → `ErrRefreshTokenInvalid` /
   `ErrRefreshTokenClaimedByOtherClient`（现有行为）。
2. 族已撤销（`TokenFamily.RevokedAt != 0`）→ `ErrRefreshTokenFamilyRevoked`。
3. secret == 当前 `Token` → 正常路径，进入轮换或窗口内复用。
4. secret == `ObsoleteToken`：
   - `now <= LastUsed + reuseInterval`（宽限期内）：
     - 该旧 secret **尚未被重用过**（行上 `ObsoleteConsumedAt` 为零）→ 唯一一次
       成功：原子地把 `ObsoleteConsumedAt` 置为当前时间，返回当前 `Token`（不再次
       轮换、不再次调 connector）。
     - `ObsoleteConsumedAt != 0`（已被并发请求消费过）→
       `ErrRefreshTokenAlreadyUsed`，映射为 `invalid_grant`
       「refresh token has already been used during its rotation grace period」。
   - `now > LastUsed + reuseInterval`（超出宽限期）：
     - 行属于某族（`FamilyID != ""`）→ **重放**：原子 claim 返回
       `ErrRefreshTokenReplayed`，事务提交后 `RevokeFamily` 标记族撤销
       （reason=`replay`，记录 `LastReplayedToken`、时间），列出并标记该族全部节点，
       删除族内刷新令牌行；写结构化安全审计日志（见 §7）；客户端收到 `invalid_grant`。
     - 行无族（历史令牌）→ 保持历史的 `ErrRefreshTokenClaimedTwice` 一次性拒绝，
       不删行、不撤销。
5. 其他 secret 不匹配 → `ErrRefreshTokenInvalid` / claim 阶段
   `ErrRefreshTokenClaimedTwice`（均为现有一次性语义）。
6. 绝对过期 / 不活动过期 → `ErrRefreshTokenExpired`（现有行为）。

原子性由 claim 所在的同一个 `UpdateRefreshToken` 事务保证（SQL 行锁、memory 互斥
锁、etcd ModRevision Txn、k8s resourceVersion CAS）。判定与状态翻转在同一事务内
提交，因此 N 个并发请求中只有一个能把 `ObsoleteConsumedAt` 从零置非零——这是存储
层 CAS，不依赖各节点时钟。Rotate 在 claim 前对族内令牌重新读取实时行，避免基于
lookup 快照做并发判定。

宽限期为 0（默认）时第 4 步的窗口分支不可达，语义与现状逐字节一致。

## 5. 配置

`expiry.refreshTokens` 下新增（复用已有 `reuseInterval` 作为宽限期开关）：

```yaml
expiry:
  refreshTokens:
    disableRotation: false
    reuseInterval: "0s"          # 宽限期；0 = 一次性失效（默认，保持现状）
    validIfNotUsedFor: "2160h"
    absoluteLifetime: "3960h"
```

启动时校验并记录：

- 宽限期必须 >= 0；非法 duration 启动报错（现有 parse 路径）。
- 宽限期 > 访问令牌有效期时打印 warning：撤销传播的有效窗口不应超过访问令牌自然
  寿命，否则配置失去意义（文档说明二者须一起调）。
- 宽限期过长（超过 `absoluteLifetime` 等）时 warning。

## 6. 降级策略

| 故障 | 行为 |
|---|---|
| 宽限期状态读写失败（存储错误） | claim 事务失败 → 刷新返回 500，**不放行** |
| 族头/节点写入失败 | 与 Rotate 同一失败路径，undoClaim 回滚 + 刷新失败 |
| introspection 读族状态基础设施错误 | 500，不返回 active=true |
| 族/节点记录缺失（信号丢失/旧数据/GC 后） | 访问令牌按 JWT 自身 exp 兜底（现有行为） |
| 进程重启 | 宽限期状态在 refresh_token 行、族/节点在持久存储，全部存活 |

## 7. 审计日志

重放是安全事件。检测到时以 `slog` Warn 级别写结构化日志，并把
reason/token/时间持久化到 `TokenFamily` 行（独立于进程内存，可事后审计）：

```
msg="refresh token replay detected; token family revoked"
family_id=... token_id=... client_id=... user_id=... connector_id=...
reason=replay observed_at=... grace_interval=... last_used=...
```

族被撤销时另有一条 `token family revoked` 日志，含节点计数。

## 8. 垃圾回收

- `access` 节点在 `ExpiresAt` 过后由 GC 清理（自然过期后无需再保留撤销登记）。
- 已撤销族的 refresh 节点在撤销时即随令牌行删除；族头保留审计记录，GC 在族内
  无任何存活节点且超过绝对寿命后清理。

## 9. 存储后端

新实体实现全部五个后端并纳入 conformance 测试：memory、sql（legacy SQLite/
Postgres/MySQL）、ent（SQLite/Postgres/MySQL）、kubernetes（CRD）、etcd（key
prefix + Txn）。所有后端的更新接口沿用现有 updater-in-transaction 模式。

## 10. 验收测试

实现已通过以下测试（memory + 两个 SQLite 后端 + k8s 模拟 apiserver）：

1. **并发压测**（`TestRotateGracePeriodConcurrentSingleWinner` 单元层 N=50，以及
   端到端 `TestRefreshGracePeriodHTTPConcurrencyAndReplay` 经真实 HTTP /token 端点
   N=50）：同一旧令牌在宽限期内并发刷新 → 成功数恰为 1，`already used` 拒绝数为
   N-1，无其他状态码；且获胜者返回的是同一个轮换后令牌，connector 只解析一次。
2. **重放灵敏度**（`TestRotateReplayOutsideGraceRevokesFamily` + 端到端）：时钟推进
   超过宽限期后再用旧令牌 → 族被标记 revoked（reason=replay，记录触发令牌），族内
   全部 refresh/access 节点 `RevokedAt != 0`，刷新行被删除，后续刷新与 introspection
   均不可用；审计日志含 family_id、token_id、client_id、user_id、时间与判定依据。
3. **族撤销传播到访问令牌**（端到端）：族撤销后，撤销前签发且自身未过期的访问令牌
   introspect 返回 `active=false`；族外令牌（`TestFamilyRevocationDoesNotTouchOtherFamilies`）
   不受影响。
4. **持久性**（`TestRotateGracePeriodStateSurvivesRestart`）：用同一存储的全新
   RefreshStore 句柄模拟重启，窗口内旧令牌仍可成功复用一次，第二次被拒——
   `ObsoleteConsumedAt` 随行持久化。legacy SQL 后端经真实迁移建表，ent 经自动迁移。
5. **默认行为不变**（`TestDefaultOneShotRotationUnchanged` + 既有
   `TestRefreshTokenExpirationScenarios` 等全套）：`reuseInterval=0` 时旧令牌第二次
   使用即 `invalid_grant`，不建族、不删行。
6. **fail-closed**（`TestFailClosedWhenFamilyStorageUnavailable`）：注入节点写/读
   故障时刷新失败而非放行，introspection 读撤销状态失败返回 500 而非 active=true。
7. **conformance**：`TokenFamilyCRUD`、`TokenFamilyConcurrentUpdate`、
   `TokenNodeGarbageCollection` 纳入 `conformance.RunTests`，在 memory、legacy SQL
   SQLite、ent SQLite、k8s 上通过；并发 conformance 经 `-race` 检测无数据竞争。

## 11. 实现索引

- 存储模型与接口：`storage/storage.go`（`RefreshToken` 新字段、8 个族图方法）、
  `storage/token_family.go`（`TokenFamily`/`TokenNode` 类型）。
- 五个后端：`storage/memory/token_family.go`、`storage/sql/token_family.go`
  （+ `migrate.go` 迁移、`crud.go` 新列与 GC）、`storage/ent/`（schema +
  生成代码 + `client/tokenfamily.go`）、`storage/etcd/token_family.go`、
  `storage/kubernetes/token_family*.go`（+ CRD manifest）。
- 核心编排：`server/tokens/family.go`（建族、注册访问节点、`RevokeFamily`、
  `IsAccessTokenRevoked`）、`server/tokens/refresh_store.go`（claim 状态机、
  宽限期 CAS、重放分类、回滚）、`server/tokens/refresh_lookup.go`（族存活校验、
  新 sentinel）、`server/tokens/refresh_strategy.go`（`GraceInterval`）。
- 端点集成：`server/grants/refresh.go`（错误映射、fail-closed、访问节点注册）、
  `server/tokens/issuer.go`（带 jti 的访问令牌签发）、
  `server/introspection/introspection.go`（访问令牌族撤销点查）。
- 配置与文档：`cmd/dex/serve.go`（宽限期/访问令牌寿命协调告警）、`config.yaml.dist`。
- 测试：`server/tokens/family_test.go`、`server/server_grant_refresh_grace_test.go`、
  `storage/conformance/token_family.go`。
