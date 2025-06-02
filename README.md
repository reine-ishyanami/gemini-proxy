# gemini-proxy

这是一个 Rust 项目，提供了一个命令行工具，用于运行服务以及管理证书（生成、安装、卸载、更新）。

## 构建

确保你已经安装了 Rust 和 Cargo。然后，在项目根目录下运行：

```bash
cargo build --release
```

这将在 `target/release/` 目录下生成可执行文件。

## 运行

你可以通过命令行参数或交互式菜单来运行程序。

### 命令行参数

```bash
./target/release/gemini-proxy [COMMAND]
```

可用命令：

*   `run`: 运行服务。
*   `generate`: 生成证书。
*   `install`: 安装证书。(未实现)
*   `uninstall`: 卸载证书。(未实现)
*   `update`: 更新证书。(未实现)

### 交互式菜单

直接运行可执行文件将显示一个交互式菜单：

```bash
./target/release/gemini-proxy
```

然后按照提示选择操作。

## 证书管理

该工具提供了生成、安装、卸载和更新证书的功能，这对于运行服务可能需要。

## 日志

项目使用了 `fern` 进行日志记录。日志配置可以在代码中找到。
