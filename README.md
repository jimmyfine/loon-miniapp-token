# Loon 小程序 Token 提取

读取已开启 MITM 的接口响应（JSON、表单）、URL 参数和请求/响应头，识别 token 字段；按域名和字段保存最新值，命中新值时发送 Loon 通知。点按通知可把完整 token 写入剪贴板。脚本只读取，始终 `$done({})`，不改写请求或响应。

仓库：<https://github.com/jimmyfine/loon-miniapp-token>

## 文件

- `miniapp-token.plugin`：在线版插件，脚本从 jsDelivr 加载。
- `miniapp-token-local.plugin`：本地版插件，引用同目录的 `miniapp-token.js`。
- `chelaila-token.plugin`：互助小程序（AppID `wxa2fa5f1353d0adaa`）专用在线版，已写入业务域名。
- `chelaila-token-local.plugin`：互助小程序专用本地版，引用同目录的 `miniapp-token.js`。
- `miniapp-token.js`：提取脚本。

## 安装

### 在线

Loon → 插件 → + → 从 URL 添加，粘贴以下任一地址：

- 国内加速：`https://cdn.jsdelivr.net/gh/jimmyfine/loon-miniapp-token@24db87fcc43ac133b37234580fc8b6a53caea167/miniapp-token.plugin`
- GitHub：`https://raw.githubusercontent.com/jimmyfine/loon-miniapp-token/24db87fcc43ac133b37234580fc8b6a53caea167/miniapp-token.plugin`

导入后在 Loon 配置文件的 `[Mitm]` 段 `hostname` 行追加目标小程序接口域名；也可以先把仓库里的 `miniapp-token.plugin` 改好域名，再用自己的地址导入。只添加小程序自己的业务接口域名，不要添加 `*.weixin.qq.com`、`*.wxs.qq.com` 等微信内部通道。确认 MITM 已开启、Loon CA 证书已信任。

插件参数 `hostAllowlist` 可限制只处理哪些域名，默认 `*` 不限制；填写 `api.example.com,*.example.org` 后，其他已 MITM 的域名会被脚本直接跳过。

### 互助小程序（AppID wxa2fa5f1353d0adaa）

业务域名 `app-chelaila.52python.cn`，登录接口 `POST /shop/user/login`，token 在响应 `data.token`，后续请求放在 `token` 请求头。专用插件已写好域名和 MITM，直接导入即可：

- 国内加速：`https://cdn.jsdelivr.net/gh/jimmyfine/loon-miniapp-token@6bd0c961e9d30c3f6a34f5109ceaf519effffbac/chelaila-token.plugin`
- GitHub：`https://raw.githubusercontent.com/jimmyfine/loon-miniapp-token/6bd0c961e9d30c3f6a34f5109ceaf519effffbac/chelaila-token.plugin`

启用后只保留这个专用插件，不要再同时启用通用插件；MITM 只保留 `app-chelaila.52python.cn`，移除 `*.weixin.qq.com`、`*.wxs.qq.com`。打开小程序触发任意接口即可；如果一直没有通知，在微信中删除该小程序（清除缓存）后重新打开，强制重新登录。

### 本地（Loon 3.2.0 及以上）

1. 把 `miniapp-token.js` 放入 `iCloud Drive/Loon/Script/`，文件名保持不变。
2. 编辑 `miniapp-token-local.plugin` 的 `[Mitm]`，把 `api.example.com` 换成小程序实际接口域名；多个域名用英文逗号分隔，支持 `*.example.com`。
3. 把 `miniapp-token-local.plugin` 放入 `iCloud Drive/Loon/Plugins/`。
4. 打开 Loon → 插件，启用“小程序 Token 提取”；确认 Loon CA 证书已安装并信任，MITM 开关已打开。

### 找接口域名

打开小程序时在 Loon 日志/请求记录中查看请求域名；只对接口域名开 MITM，不要覆盖整站或 CDN。

## 配置

修改 `miniapp-token.js` 顶部 `CONFIG`；在线版可在 Loon 插件参数中调整 `hostAllowlist` 和 `debug`，其余字段使用本地版修改：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `webhook` | 空 | 填写后把命中项 POST 为 JSON；留空只发通知 |
| `extraKeys` | 空 | 额外识别的字段名，如 `["ticket", "sid"]`；默认匹配字段名含 `token` 的字符串字段和 `jwt` |
| `minTokenLength` | 16 | 短于该长度的值不当作 token |
| `notifyAll` | false | 一次响应有多个 token 时是否全部通知，默认只通知得分最高的一条 |
| `notifyOnChangeOnly` | true | 相同值不重复通知 |
| `captureRequestHeaders` | true | 同时检查请求头中的 Authorization、token 等 |
| `showFullToken` | false | 通知正文显示掩码；设为 true 显示完整 token |
| `hostAllowlist` | 空 | 只处理这些域名，支持 `*.example.com`；空表示不限制 |
| `debug` | false | 输出 `[miniapp-token]` 日志，便于在 Loon 日志中排查 |

在线版脚本从 jsDelivr 加载，修改仓库后可能有缓存延迟；需要立即生效时使用本地版。

Webhook 请求体：

```json
{
  "source": "loon-miniapp-token",
  "time": "2026-11-09T03:00:00.000Z",
  "host": "api.example.com",
  "url": "https://api.example.com/login",
  "status": 200,
  "tokens": [
    { "field": "access_token", "value": "…", "source": "响应体" }
  ]
}
```

填写 webhook 时，该次接口响应会等待 webhook 返回或 3 秒超时后再放行；留空不产生额外延迟。

## 使用

打开目标小程序并触发登录或刷新接口。命中后收到标题为“小程序 Token”的通知，副标题为域名和字段名；点按通知后完整 token 在剪贴板。

最新值保存在 Loon 本地存储键 `miniapp_token_store`，按“域名 + 字段”去重，最多保留 80 条。

## 排查

- 没有通知：MITM 域名与小程序接口域名不一致；MITM 未开启或证书未信任；小程序对接口启用了证书固定。
- 出现 `Convert body string error: 无法解码数据块为UTF-8字符串`：匹配到了微信 `mmtls` 等二进制通道。v1.1 已改为二进制模式并在脚本内跳过 `*.weixin.qq.com`、`*.wxs.qq.com`、`/mmtls/` 和静态资源；同时把这类域名从 `[Mitm]` 中移除，只保留小程序业务接口域名。
- 有请求但没有命中：字段名不含 `token`，或值短于 16 字符；把字段名加入 `extraKeys`，或调低 `minTokenLength`。
- 找不到接口域名：查看 Loon 日志/请求记录中打开小程序时的请求域名；只对接口域名开 MITM，不要覆盖整站或 CDN。
