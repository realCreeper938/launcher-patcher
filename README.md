# launcher-patcher

为启动器移除区域或下载限制，生成 `_patched` 副本，原文件不会被修改。支持 Windows x64 / ARM64。

## 支持

| 启动器 | 处理结果 |
| --- | --- |
| PCL2 2.99 及以后 | 恢复 MC 下载页与版本修改页 |
| PCL2 2.99 之前 | 无需处理 |
| PCL CE | 移除区域限制 |
| HMCL | 移除区域限制 |

PCL CE 是 PCL2 的社区分支，两者分别处理。

## 使用

把启动器文件拖到程序图标或窗口里，或运行：

```text
launcher-patcher.exe <文件> [更多文件...]
```

输出文件为 `原文件名_patched.ext`；已存在时依次使用 `_2`、`_3` 后缀。日志位于 `%LOCALAPPDATA%\launcher-patcher\last.log`。

## 注意

- PCL2 2.99 的整合包安装功能在发布时已被编译移除，无法恢复；MC 下载和版本修改可用。
- 修改后的 HMCL 会被视为非官方版本，Microsoft 登录和自动更新可能不可用；本工具不会伪造签名。
- 程序不联网、不上传任何文件。
- 仅用于你有权修改的启动器文件。

## 构建

仅通过 GitHub Actions 构建和发布。
