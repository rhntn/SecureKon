# SecureKon — Simple Secure DNS Manager

**[Download / İndir / Herunterladen / 下载](https://github.com/rhntn/SecureKon/raw/refs/heads/main/downloads/SecureKonSetup.exe)** · Windows 11 x64 · v2.0.0 · Rust

Created by **[OMTY](https://labs.omty.io)**

## Türkçe
Windows, Chrome ve Edge için şifreli DNS yöneticisi. AdGuard, Google, Cloudflare veya özel IPv4/IPv6 adresleri uygular. Kurulumu aç, **Kur** seçeneğine bas; ardından sağlayıcı seçip **Kaydet ve uygula** düğmesine tıkla. **Başlangıçta çalıştır** anında kaydedilir; kapatmak DNS ayarlarını değiştirmez.

## English
Encrypted DNS manager for Windows, Chrome and Edge. Applies AdGuard, Google, Cloudflare or custom IPv4/IPv6 settings. Run setup, click **Install**, select a provider and **Save and apply**. **Run at sign-in** is saved immediately; disabling it leaves DNS settings unchanged.

## Deutsch
Verwaltung für verschlüsseltes DNS unter Windows, Chrome und Edge. Unterstützt AdGuard, Google, Cloudflare sowie eigene IPv4-/IPv6-Adressen. Setup öffnen, **Installieren**, Anbieter wählen und **Speichern und anwenden**. **Bei Anmeldung starten** wird sofort gespeichert; Ausschalten ändert die DNS-Einstellungen nicht.

## 简体中文
适用于 Windows、Chrome 和 Edge 的加密 DNS 管理器。支持 AdGuard、Google、Cloudflare 及自定义 IPv4/IPv6 地址。运行安装程序，点击 **安装**，选择提供商，然后点击 **保存并应用**。**登录时启动** 的更改立即保存；关闭不会更改 DNS 设置。

## Build
Windows: Rust stable and Visual Studio C++ Build Tools with Windows SDK. Run `build.cmd`. The lockfile fixes dependency versions. Linux cross compilation uses the `x86_64-pc-windows-gnu` Rust target and MinGW-w64.
