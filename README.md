# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方立即撤销凭证；存在待生效预约时返回 409，需先撤回预约。
- `POST /api/credentials/{id}/revocation-appointments/schedule`：登记预约撤证（凭证、原因、未来生效时间），同一凭证只允许一条未结预约。
- `POST /api/revocation-appointments/{id}/withdraw`：生效前撤回预约，原凭证照常使用；已到生效时间则拒绝。
- `GET /api/revocation-appointments`：查看待生效、已撤回、已生效的撤证预约记录。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 预约撤证语义

撤证决定常到夜间才生效，因此撤销与凭证状态写入分离维护：

- 登记预约时凭证仍为 `active`，白天核验（以及签发、争议入口）先把到点的预约落实为撤销，未到点的不改动凭证。
- 核验按请求中的 `at` 时刻判定：生效时刻之前返回原结论 `valid_until_revocation`，并附 `revocation_starts_at`、`revocation_reason` 说明失效时间；生效时刻及之后返回 `revoked`。历史时刻回放也按当时结论判定。
- 预约生效前可撤回，撤回后核验恢复 `valid`，且可重新登记预约。
- 预约到点后凭证才转为 `revoked`，唯一有效凭证索引随之释放，同一持有人才可被再签一张。
- 判定逻辑（`RevocationScheduler.effect_for`）、凭证写入（`CredentialService.write_revocation`）与页面展示（`appointment_view`）三处分开维护。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
