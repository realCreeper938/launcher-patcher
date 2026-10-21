# launcher-patcher

一个用纯 Go 编写的小型启动器区域限制补丁工具，支持 Windows x64 / ARM64。

把启动器文件拖到程序图标上，或双击打开后拖入窗口，程序会自动识别并把修补后的副本生成在原文件旁边。**原文件不会被修改。**

## 支持的文件

| 文件 | 处理方式 |
| --- | --- |
| PCL CE（`PCL2_CE_Release_*.exe`） | 定位 `PCL.Core.App.Region.RegionAssessment.get_IsRestricted` 的 IL，把返回值常量改为 `false` |
| HMCL（`.jar` / `.exe`） | 定位 `RegionUtils.<clinit>` 中的 `checkMachineIsChinaMainland()` 调用，替换为 `iconst_0; nop; nop` |
| 原版 PCL（`Plain Craft Launcher`） | 原版没有同类区域限制，只提示，不生成文件 |

输出文件命名为 `原文件名_patched.ext`；如果已存在，会依次使用 `_patched_2`、`_patched_3` 等后缀。

## 两种使用方式

### 拖到程序图标上

不显示窗口，直接处理，结束后退出。适合批量拖入多个文件。

### 双击打开

窗口中央显示一个拖拽图标，下方居中显示：

```text
将要修补的启动器文件拖到此窗口
```

把文件拖进窗口后自动开始修补，生成文件后窗口自动关闭。若出错，错误信息和日志路径会保留在窗口里。

命令行方式同样可用：

```text
launcher-patcher.exe <文件> [更多文件...]
```

## 日志

运行日志写入：

```text
%LOCALAPPDATA%\launcher-patcher\last.log
```

程序不联网、不上传任何文件。

## 关于 HMCL 签名

HMCL 使用 `META-INF/hmcl_signature` 做官方性校验。修改 `RegionUtils.class` 后该签名必然失效，本工具不会伪造签名。由此带来的结果是：

- HMCL 会把修补后的文件视为非官方版本；
- 依赖官方身份的 Microsoft 账户登录可能不可用；
- HMCL 的自动更新可能不可用（这也避免了更新后限制重新出现）；
- 其余下载、启动和离线账户功能正常。

同时，HMCL 会把本机视为“非中国大陆环境”，因此不再自动优先使用中国大陆镜像。可在 HMCL 设置中手动选择下载源。

## 实现说明

- 纯标准库，无第三方依赖、无 CGO，Windows GUI 子系统，发布体积小。
- HMCL 通过解析 class 常量池定位方法引用，不依赖固定常量池下标。
- PCL CE 通过解析 .NET 单文件包中的内嵌 PE / ECMA-335 元数据，按命名空间和类型名定位方法，不依赖包内偏移。
- HMCL exe 保留前置的原生启动器字节，仅重建其后的 jar。
- 输出先写入同目录临时文件，校验成功后再改名，避免留下半成品。

## 构建

**只在 GitHub Actions 中构建。** 工作流依次执行：

1. `go test ./...`（Linux 单元测试）
2. 下载固定版本的 PCL CE / HMCL 样本做真实文件端到端验证
3. 交叉编译 `windows/amd64` 与 `windows/arm64`
4. 推送 `v*` 标签时创建 Release，附带两个 exe 和 `SHA256SUMS`

本地不需要安装 Go，也不要在本地构建发布产物。

## 限制

- HMCL 使用 Zip64 的归档暂不支持。
- PCL CE 只处理无压缩、IL-only 的内嵌程序集；这是官方单文件发布的格式。
- 本工具只适用于你有权修改的启动器文件，不提供任何签名伪造能力。
