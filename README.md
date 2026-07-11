# Kokkoro Star Island Blog

一个幻想系二次元个人博客，拥有真正可用的文章后台，以及分别设计的桌面端和手机端界面。

线上演示：<https://demo.kokkoro.xyz/>

## 功能

- 桌面端角色场景、任务式文章入口和悬浮音乐播放器
- 手机端独立布局、底部 Dock 和抽屉式收藏夹
- 动态时间问候、随机星语和柔和跨屏流星
- 文章阅读、收藏、下一篇和 Hash 直达
- 管理员登录、草稿、发布、编辑和删除
- SQLite 持久化存储
- 本地 WAV 默认背景音乐、MP3 兼容回退与播放进度
- 响应式、安全区和键盘操作支持

## 运行

需要 Python 3.10+，不依赖第三方 Python 包。

```bash
export BLOG_ADMIN_PASSWORD='请设置强密码'
export BLOG_SESSION_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export BLOG_HOST=127.0.0.1
export BLOG_PORT=8090
python3 server.py
```

然后访问 <http://127.0.0.1:8090>。

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `BLOG_ADMIN_PASSWORD` | 创作后台密码，生产环境必须设置 | 无安全默认值 |
| `BLOG_SESSION_SECRET` | Cookie 签名密钥，生产环境必须设置 | 进程内随机值 |
| `BLOG_ROOT` | 静态资源根目录 | 当前项目目录 |
| `BLOG_DB` | SQLite 数据库路径 | `data/blog.db` |
| `BLOG_HOST` | 监听地址 | `127.0.0.1` |
| `BLOG_PORT` | 监听端口 | `8090` |

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 部署建议

生产环境建议：

1. 使用 systemd 运行 `server.py`。
2. 仅监听 `127.0.0.1`。
3. 使用 Caddy 或 Nginx 提供 HTTPS 反向代理。
4. 将环境变量保存在仓库之外，并设置严格文件权限。
5. 定期备份 `data/blog.db`。

## 数据与隐私

- 数据库、环境变量、服务器备份和管理员凭据不会提交到 Git。
- 收藏记录只保存在访客浏览器的 `localStorage` 中。
- 仓库包含网页使用的压缩版背景音乐。请确保部署者拥有相应使用权。

## License

源代码采用 MIT License。图片和音频资源不随 MIT License 授权，相关权利归各自权利人所有。
