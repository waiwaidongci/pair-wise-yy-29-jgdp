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
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。传 `effective_at` 即登记撤销预约：到点前核验仍返回原有结论并注明失效时间（`valid_until_revocation`），到点后才按撤销处理；不传则立即生效。同一凭证只保留一条未结预约，生效前可撤回。
- `POST /api/revocation-appointments/{id}/withdraw`：签发方在生效前撤回撤销预约，原凭证照常使用。
- `GET /api/revocation-appointments[?status=pending|withdrawn|effective]`：查看待生效、已撤回、已生效的撤销预约记录；`/revocations` 页面按这三类分组展示。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 预约撤证的职责划分

- `RevocationScheduler`：撤销预约的登记与判定（某时刻是待生效、已生效还是已撤回），只维护 `revocation_appointments` 表。
- `CredentialService`：凭证状态的写入（到点结算后把凭证置为 `revoked`）与签发、核验等业务流程。
- `static/revocations.html`：撤销预约的页面展示，与上述逻辑分开维护。

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
