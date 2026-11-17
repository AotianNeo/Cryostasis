# Cryostasis

[English](README.md) | [简体中文](README_zh.md)

**Cryostasis** 是一个面向小米 HyperOS / MIUI 的零硬编码自适应 LSPosed 引擎：当系统进入低电量 30 秒关机倒计时并到达临界点时，Cryostasis 会拦截原本的关机指令，改为将设备切入**超级省电模式（Ultra Battery Saver）**——在真正耗尽电芯前保留基础通信与当前运行上下文。

与绑定单一版本的传统 Xposed 模块不同，Cryostasis 内置了**运行时 DEX 字节码锚点定位器**。无论手机管家（`com.miui.securitycenter`）如何升级或被 R8/ProGuard 混淆（如 `z7.x.R`、`I7.B.Q0` 等随版本变化的符号），模块都会在冷启动时通过跨版本稳定的字符串锚点动态反查真实类名与方法签名，并按宿主版本号缓存在本地。

---

## 四层自适应架构

1. **运行时 DEX 锚点定位 + 版本缓存**（[`DexLocator.java`](app/src/main/java/io/github/aotianneo/cryostasis/DexLocator.java)）
   - 缓存键为 `versionCode + lastUpdateTime + apkPath`，同一版本后续启动免扫描直接命中。
   - 宿主更新导致缓存失效时，直接解析 Base / Split APK 根目录 `classes*.dex` 的字符串表与 Dalvik 指令流（`const-string` / `const-string/jumbo`），依据稳定锚点与方法原型锁定：
     - 30 秒到期关机触发函数（锚点 `charger,low-battery`，签名 `()V`）及实例 `Context` 字段
     - 倒计时入口函数（锚点 `Already displayed power off countdown`，签名 `()V`）
     - 关机发送工具方法（锚点 `REQUEST_SHUTDOWN` / `ACTION_REQUEST_SHUTDOWN`）
     - 备用超级省电静态入口（锚点 `changeSuperPowerMode` + `POWER_SUPERSAVE_MODE_OPEN`）
2. **主用户隔离与防循环守卫**（[`CryostasisHook.java`](app/src/main/java/io/github/aotianneo/cryostasis/CryostasisHook.java)）
   - 严格限定只在主用户（`user 0`）触发低电截停并进入超级省电；同时在分身/工作空间（非 `0` 号用户）拦截 `PowerSaverProvider` 与动态定位到的 `switchSuperPower(true, ...)` 进入动作，防止双用户并发进入超级省电互相覆盖跨用户共享的全面屏手势（`force_fsg_nav_bar`）、动画缩放与 `UiModeManagerService` 暗色模式状态。
   - 倒计时前置同时检查 `power_supersave_mode_open` 与同步写入的 `pc_security_center_super_power_mode_enter_local` 并附带 10 秒冷却锁，防止粘性广播与延迟写入窗口期内重复弹窗；对 `reason == null` 的定时关机（MIUI 12.2–HyperOS 1.0）及非低电关机原因完全放行。
3. **与混淆无关的 Framework 兜底拦截**
   - Hook `ContextWrapper` 与 `ContextImpl` 的 `startActivity`、`sendBroadcast`，兜底截获直接发出的系统关机 Intent。
4. **三通道切入超级省电 & 动态文案本地化**
   - 按顺序通过 `content://com.miui.powercenter.powersaver`（`changeSuperPowerMode`）→ 动态定位的静态辅助函数 → `Settings.System` 切入超级省电。
   - 运行时通过 `Resources.getIdentifier` 动态获取 `power_off_warning_message`、`power_off_warning_notification_title`、`power_off_warning_notification_message` 资源 ID，实时将弹窗与通知倒计时文案改写为“即将进入超级省电模式”（保留动态秒数）。

---

## 使用说明

1. 安装好 **LSPosed** 的小米 / Redmi / POCO 设备（MIUI / HyperOS）
2. 安装 [Releases](https://github.com/AotianNeo/Cryostasis/releases) 发布的 `Cryostasis.apk` 或自行源码编译安装
3. 在 LSPosed 管理器中启用 **Cryostasis**，确认作用域勾选 **手机管家**（`com.miui.securitycenter`）
4. 强行停止手机管家或重启一次即可生效

---

## 从源码构建

仅依赖标准 JDK（`javac`、`keytool`）、Android SDK（`platforms` 与 `build-tools`）及 Python 3 标准库，无需启动 Gradle 守护进程即可秒级产出已签名安装包（同时保留完整 Gradle 配置便于 Android Studio 打开）：

```bash
git clone https://github.com/AotianNeo/Cryostasis.git
cd Cryostasis
python3 tools/build_apk.py
```

构建并经 `apksigner verify` 校验通过的 APK 会输出至 `build/Cryostasis.apk`。

---

## 开源协议

[MIT](LICENSE)
