# task027-rbac — RBAC 权限规则求值引擎

基于角色的访问控制（RBAC）规则求值引擎。维护角色定义与用户授权关系，支持角色多继承、显式拒绝与拒绝优先（deny-overrides）求值。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康检查 |
| POST | `/roles` | 创建或更新角色（覆盖） |
| POST | `/grant` | 给用户授予角色（幂等） |
| POST | `/check` | 权限判定，返回 `allow`/`deny`/`undefined` |
| POST | `/permissions` | 查询用户全部可达权限清单 |

权限点格式：`资源:动作`，如 `doc:read`。

## 求值规则

1. 可达角色 = 用户已授予角色沿 `parents` 传递闭包展开的全部角色。
2. 合并所有可达角色的 `allow` 与 `deny`。
3. **拒绝优先**：权限点出现在 `deny` 集合即返回 `deny`；否则出现在 `allow` 集合返回 `allow`；否则 `undefined`。

## 边界约束

- 循环继承检测：新增继承形成环则拒绝，且不破坏现有角色图。
- 未知角色引用：`parents` 或授予操作引用不存在的角色 ID 则拒绝。
- 权限点格式校验：`allow`/`deny` 与判定入参必须符合 `资源:动作` 格式。

## 运行

```bash
# 自检
go run -mod=vendor . --smoke-test
# 服务
go run -mod=vendor . server --addr :8080
```

## 工具链

Go 1.26.3、`GOTOOLCHAIN=local`、仅标准库、CGO_ENABLED=0、Docker 双架构（linux/amd64、linux/arm64）。
