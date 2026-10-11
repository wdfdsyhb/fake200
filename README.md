# fake200

**Detect WAF "fake 200" block pages and soft-404s that poison your batch recon results.**
识别批量扫描里的"假 200"——WAF 拦截页和 CMS 软 404，它们让你的扫描结果虚高。

## 问题

批量扫资产时最常见的坑：WAF 对**任意路径**都返回 `200 + 拦截页`，脚本把拦截页当成了有效页面；CMS 的软 404（返回 200 的"页面不存在"）同样污染结果。等手动点开才发现整页全是废数据。

## 工作原理

对每个目标 URL（1 次请求）+ 同源随机路径基线（默认 2 次请求）：

1. **厂商指纹**：响应体命中 12 组已知 WAF 拦截页特征（Cloudflare / 阿里云 / 腾讯 / 雷池 / 安全狗 / 创宇盾 / 宝塔 / 百度云加速 / Incapsula / Akamai / F5 / ModSecurity）。要求目标与随机路径基线**同时**命中才判 FAKE200，避免页面里恰好提到厂商名就误报；
2. **随机路径基线**：向同源请求 `/f2k-<随机>.html` 这类必然不存在的路径。真站返回 404/403；返回"和目标长得一样"的 200 就是墙；
3. **相似度分级**：归一化（去数字、折叠空白、转小写）后与基线比对。`>= 0.90` → `FAKE200`；`0.70–0.90` → `SUSPECT`（多为 CMS 软 404 / 共用模板）；否则 `OK`。

这是启发式判定，双向都可能误报，重要目标请人工复核。

## 安装与使用

```bash
pip install requests
python fake200.py https://target.com/admin            # 单个 URL
python fake200.py -f urls.txt -t 20 -o result.json    # 批量 + 并发 + 导出
cat urls.txt | python fake200.py -                    # stdin
python fake200.py https://site.com --proxy http://127.0.0.1:8080 --insecure
```

示例输出（真实运行）：

```
[ok]       200      577  https://example.com  | baseline status: 404

1 targets | FAKE200=0 SUSPECT=0 OK=1 SKIP/ERROR=0
```

命中时的样子：

```
[FAKE200]  200    51234  http://t1.com/admin  | vendor=cloudflare on target & baseline
[SUSPECT]  200    18220  http://t3.com/item/1 | baseline sim=0.82 (soft-404/shared template?)
```

## 判定等级

| verdict | 含义 |
|---|---|
| `FAKE200` | 高置信：厂商指纹双命中，或基线相似度 >= 0.90 |
| `SUSPECT` | 疑似：相似度 0.70–0.90（软 404 / 模板页），或仅目标命中关键词 |
| `OK` | 200 看起来真实（基线 404/403，或内容明显不同） |
| `SKIP` / `ERROR` | 非 200 状态码 / 网络失败 |

## 与同类工具的关系

- `wafw00f`：识别 WAF 类型，不回答"你这个 200 是不是假的"
- `httpx`：存活探测，默认把拦截页也算 alive
- `ffuf` / `gobuster` / `feroxbuster`：目录爆破时内置了 wildcard 校准，但只服务于自己的扫描
- `fake200`：独立的一层"结果可信度检查"，输入是任意 URL 列表（httpx 结果、爬虫输出、批量扫描产物都行）

## 参数速查

| 参数 | 默认 | 说明 |
|---|---|---|
| `-t` | 10 | 并发数 |
| `--baselines` | 2 | 每个目标的随机基线路径数 |
| `--threshold` | 0.90 | FAKE200 相似度阈值 |
| `--timeout` | 10 | 单请求超时（秒） |
| `--proxy` / `--insecure` | - | 走代理 / 跳过 TLS 校验 |
| `-o` / `--csv` | - | 导出 JSON / CSV |
| `-q` | - | 只输出 FAKE200 / SUSPECT / ERROR |
| `--fail` | - | 发现 FAKE200 时退出码置 2，方便接脚本 |

## 局限

- 纯前端渲染、body 无特征的拦截页测不到；多数 JS 挑战页源码里仍有服务端特征，可以命中
- 相似度基于前 6000 个归一化字符，超长页面只比对头部
- 每个目标额外多 `--baselines` 个请求，大批量时注意流量
- 不发送任何 payload，只做 GET 探测

## 仅用于授权测试

只对你有授权的资产使用。本人对滥用不承担责任。

## License

MIT
