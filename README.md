# openwrt-passwall-rust (passwall2-rs)

**PassWall 2 for OpenWrt, rewritten in Rust with a modern LuCI JS frontend.**

[English](#english) | [فارسی](#فارسی)

---

## English

`passwall2-rs` is a drop-in replacement for
[luci-app-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2). It keeps the
same configuration (`/etc/config/passwall2`, `/etc/config/passwall2_server`), the same
options and defaults, the same pages and workflow. Under the hood, the Lua and shell
scripts are replaced by one static Rust binary, and the CBI pages by client-side LuCI
JavaScript views.

### Features

* **Same behavior as upstream**: start/stop sequence, transparent proxy (nftables/fw4 and
  iptables/fw3), DNS (dnsmasq / chinadns-ng), shunt rules, ACLs, SOCKS services, HAProxy load
  balancing, server side, subscriptions, share links, geo rule updates, backup/restore,
  logs and component updates.
* **Xray and sing-box** config generation, matching upstream option for option.
* **No Lua at runtime**: one multicall binary, `/usr/bin/passwall2`, fully static (musl). It
  handles the service, the firewall, DNS, subscriptions and the rpcd backend
  (`luci.passwall2` ubus object).
* **Modern UI**: cards, a status dashboard, badges, responsive tables and dark-mode support.
  It works with bootstrap, argon and material themes. The upstream translations (zh-cn,
  zh-tw, fa, ru) still apply.
* Packages for **opkg (OpenWrt 23.05 / 24.10)** and **apk (OpenWrt 25.x)**.

### Install (one command)

Run this on the router, over SSH:

```sh
wget -qO- https://github.com/ParsaKSH/openwrt-passwall-rust/releases/latest/download/install.sh | sh
```

or, to save the script first:

```sh
wget -O /tmp/install.sh https://github.com/ParsaKSH/openwrt-passwall-rust/releases/latest/download/install.sh
sh /tmp/install.sh
```

The installer does the following:

1. Detects the OpenWrt release, the architecture and the package manager.
2. Downloads the matching packages and verifies their checksums.
3. Adds the Openwrt-Passwall `passwall_packages` feed if dependencies such as `geoview` or
   `tcping` are missing.
4. Removes the original `luci-app-passwall2` if it is installed, keeping your configuration.
5. Installs the recommended extras, the same defaults as upstream: Xray/sing-box,
   dnsmasq-full, nft/iptables modules, chinadns-ng, haproxy and the shadowsocks plugins.
6. Restarts the service.

Options (pass them after `sh -s --`, for example `... | sh -s -- --minimal`):

| option | meaning |
|---|---|
| `--version v26.11.0` | install a specific release |
| `--mirror https://gh-proxy.org/` | download through a GitHub mirror/proxy prefix |
| `--minimal` | only the packages and their hard dependencies |
| `--no-feed` | never add the Openwrt-Passwall packages feed |
| `--no-dnsmasq-full` | keep the stock dnsmasq |
| `--force` | reinstall the same version |
| `--uninstall` | remove passwall2-rs (configuration is kept) |

Supported architectures, with prebuilt packages: `x86_64`, `aarch64_*`, ARMv7 (`arm_cortex-a5/a7/a8/a9/a15*`),
ARMv6 (`arm_arm1176jzf-s_vfp`, `arm_mpcore`), ARMv5 (`arm_arm926ej-s`, `arm_xscale`), `i386_pentium4`,
`i386_pentium-mmx`, `riscv64_*` and `loongarch64_generic`. The full table is in
[packaging/arches.txt](packaging/arches.txt). For MIPS (`mipsel_24kc`, `mips_24kc`, ...) and PowerPC there is
no prebuilt Rust standard library. Build those with the OpenWrt SDK; see [Building](#building).

### Migrating from luci-app-passwall2

No manual migration is needed. The configuration format is identical.

* `install.sh` stops the old service and removes `luci-app-passwall2` and
  `luci-i18n-passwall2-*`. It keeps `/etc/config/passwall2`, `/etc/config/passwall2_server`,
  `/usr/share/passwall2/direct_ip` and `/usr/share/passwall2/domains_excluded`, then installs
  `passwall2-rs` + `luci-app-passwall2-rs`.
* The new package *provides* `luci-app-passwall2`, so packages that depend on it remain
  satisfied. It also *conflicts* with `luci-app-passwall2`, so only one of the two can be
  installed.
* The translations are built into `luci-app-passwall2-rs`, so the separate
  `luci-i18n-passwall2-*` packages are not needed.
* To go back, run `sh install.sh --uninstall` and then install the original package. Your
  configuration stays in place.

Manual installation also works: download `passwall2-rs_<arch>.ipk` and
`luci-app-passwall2-rs_all.ipk` from the release, then run
`opkg install ./passwall2-rs_<arch>.ipk ./luci-app-passwall2-rs_all.ipk`. On OpenWrt 25.x, use
`apk add --allow-untrusted ./passwall2-rs_<arch>.apk ./luci-app-passwall2-rs_noarch.apk`. The
dependencies `geoview` and `tcping` come from the Openwrt-Passwall packages feed.

### Building

#### Release packages without the SDK (`packaging/build.sh`)

`packaging/build.sh` cross-compiles the crate with `cargo` for musl targets, linked with
`rust-lld`, so no C cross toolchain is needed. It then assembles the packages directly:

* ipk files with the same layout as OpenWrt's `ipkg-build`
* APK v3 files with `apk mkpkg` (apk-tools 3), taken from `$APK`, from `apk` in `PATH`, or
  from the `alpine:3.23` docker image
* translations compiled with `po2lmo`, which is built from the LuCI sources

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
                  armv7-unknown-linux-musleabihf arm-unknown-linux-musleabihf
packaging/build.sh                       # core arches -> dist/
ARCHES=all packaging/build.sh            # every arch in packaging/arches.txt (runs rustup target add)
ARCHES="x86_64 arm_cortex-a7_neon-vfpv4" packaging/build.sh
packaging/test.sh                        # structural checks of the produced packages
```

Output:

* `dist/ipk/<arch>/`, `dist/apk/<arch>/`: versioned packages
* `dist/release/`: flat, version-less names (the GitHub release assets that `install.sh`
  downloads) plus `SHA256SUMS`

In this repository, builds run on the build VM (`scripts/vm.sh 'packaging/build.sh'`).
`packaging/fetch-dist.sh` copies `dist/` back. The GitHub workflow
[.github/workflows/build.yml](.github/workflows/build.yml) builds every arch and publishes a
release when a `v*` tag is pushed.

#### Inside the OpenWrt SDK / buildroot

`luci-app-passwall2/Makefile` is a regular feed package. It uses `rust/host` from the
packages feed for the binary and the standard `luci.mk` for the LuCI part, and it also
produces `luci-i18n-passwall2-<lang>`. It covers every arch OpenWrt's Rust supports,
including MIPS.

```sh
echo "src-git passwall2rs https://github.com/ParsaKSH/openwrt-passwall-rust.git" >> feeds.conf.default
./scripts/feeds update -a && ./scripts/feeds install -a
make menuconfig        # LuCI -> Applications -> luci-app-passwall2-rs
make package/luci-app-passwall2-rs/compile V=s
```

### Layout

| path | content |
|---|---|
| `passwall2/` | Rust crate (binary `passwall2`) |
| `luci-app-passwall2/` | OpenWrt package: `htdocs/` (LuCI JS views), `root/` (init scripts, hotplug, uci-defaults, data files, rpcd plugin), `po/` (translations), `Makefile` (SDK build) |
| `packaging/` | SDK-less package builder, arch table, package checks |
| `install.sh` | router installer |
| `docs/` | architecture and upstream behavior specifications |

License: GPL-3.0-only, the same as upstream PassWall 2.

---

<div dir="rtl">

## فارسی

`passwall2-rs` جایگزینی مستقیم برای
[luci-app-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2) است و همان
پیکربندی (`/etc/config/passwall2` و `/etc/config/passwall2_server`)، همان گزینه‌ها و مقادیر
پیش‌فرض، و همان صفحه‌ها و روند کار را حفظ می‌کند. در پشت صحنه، اسکریپت‌های Lua و شل با یک
باینری ایستای Rust جایگزین شده‌اند و صفحه‌های CBI با نماهای جاوااسکریپتی LuCI که در مرورگر اجرا
می‌شوند.

### ویژگی‌ها

* **رفتار یکسان با نسخهٔ اصلی**: ترتیب شروع و توقف سرویس، پروکسی شفاف (nftables/fw4 و
  iptables/fw3)، DNS (dnsmasq و chinadns-ng)، قوانین تفکیک (Shunt)، ACL، سرویس‌های SOCKS،
  توزیع بار با HAProxy، بخش سرور، اشتراک‌ها (Subscription)، لینک‌های اشتراک‌گذاری، به‌روزرسانی
  قوانین geo، پشتیبان‌گیری و بازیابی، گزارش‌ها و به‌روزرسانی اجزا.
* ساخت پیکربندی **Xray و sing-box**، گزینه به گزینه مطابق نسخهٔ اصلی.
* **بدون Lua در زمان اجرا**: یک باینری چندکاره، `/usr/bin/passwall2`، کاملاً ایستا (musl). این
  باینری سرویس، فایروال، DNS، اشتراک‌ها و بک‌اند rpcd (شیء ubus با نام `luci.passwall2`) را
  اداره می‌کند.
* **رابط کاربری مدرن**: کارت‌ها، داشبورد وضعیت، نشان‌ها، جدول‌های واکنش‌گرا و پشتیبانی از حالت
  تیره. با پوسته‌های bootstrap، argon و material کار می‌کند و ترجمه‌های نسخهٔ اصلی (از جمله فارسی)
  همچنان اعمال می‌شوند.
* بسته برای **opkg (OpenWrt 23.05 و 24.10)** و **apk (OpenWrt 25.x)**.

### نصب با یک دستور

این دستور را روی روتر، از طریق SSH، اجرا کنید:

```sh
wget -qO- https://github.com/ParsaKSH/openwrt-passwall-rust/releases/latest/download/install.sh | sh
```

اسکریپت نصب این کارها را انجام می‌دهد:

1. نسخهٔ OpenWrt، معماری و مدیر بسته (opkg یا apk) را تشخیص می‌دهد.
2. بسته‌های مناسب را دانلود می‌کند و checksum آن‌ها را بررسی می‌کند.
3. اگر وابستگی‌هایی مثل `geoview` یا `tcping` موجود نباشند، مخزن `passwall_packages` پروژهٔ
   Openwrt-Passwall را اضافه می‌کند.
4. اگر `luci-app-passwall2` اصلی نصب باشد، آن را حذف می‌کند و تنظیمات شما را نگه می‌دارد.
5. موارد پیشنهادی را نصب می‌کند (همان پیش‌فرض‌های نسخهٔ اصلی): Xray/sing-box، dnsmasq-full،
   ماژول‌های nft/iptables، chinadns-ng، haproxy و افزونه‌های shadowsocks.
6. سرویس را دوباره راه‌اندازی می‌کند.

گزینه‌ها را بعد از `sh -s --` بنویسید، مثلاً `... | sh -s -- --minimal`. اگر دسترسی به
GitHub محدود است، از `--mirror https://gh-proxy.org/` استفاده کنید. گزینه‌های دیگر:

* `--version v26.11.0`: نصب یک نسخهٔ مشخص
* `--minimal`: فقط بسته‌ها و وابستگی‌های اجباری
* `--no-feed`: مخزن Openwrt-Passwall اضافه نشود
* `--no-dnsmasq-full`: همان dnsmasq پیش‌فرض نگه داشته شود
* `--force`: نصب دوبارهٔ همان نسخه
* `--uninstall`: حذف passwall2-rs (تنظیمات نگه داشته می‌شود)

معماری‌هایی که بستهٔ آماده دارند: `x86_64`، همهٔ `aarch64_*`، ARMv7 (`arm_cortex-a5/a7/a8/a9/a15*`)،
ARMv6، ARMv5، i386، riscv64 و loongarch64. فهرست کامل در [packaging/arches.txt](packaging/arches.txt)
است. برای MIPS (مثل `mipsel_24kc` و `mips_24kc`) و PowerPC بستهٔ آماده وجود ندارد؛ آن‌ها را با
SDK اوپن‌وی‌آرتی بسازید (پایین‌تر را ببینید).

### مهاجرت از luci-app-passwall2

به مهاجرت دستی نیازی نیست، چون قالب پیکربندی دقیقاً همان است.

* `install.sh` سرویس قدیمی را متوقف می‌کند و `luci-app-passwall2` و `luci-i18n-passwall2-*` را حذف
  می‌کند. فایل‌های `/etc/config/passwall2`، `/etc/config/passwall2_server`،
  `/usr/share/passwall2/direct_ip` و `/usr/share/passwall2/domains_excluded` حفظ می‌شوند.
* بستهٔ جدید نام `luci-app-passwall2` را *فراهم* می‌کند (Provides)، پس بسته‌هایی که به آن وابسته‌اند
  همچنان کار می‌کنند. همچنین با آن *ناسازگار* است (Conflicts)، پس فقط یکی از این دو می‌تواند نصب
  باشد.
* ترجمه‌ها داخل خود `luci-app-passwall2-rs` قرار دارند و به بسته‌های جداگانهٔ
  `luci-i18n-passwall2-*` نیازی نیست.
* برای بازگشت به نسخهٔ اصلی، `sh install.sh --uninstall` را اجرا کنید و سپس بستهٔ اصلی را نصب
  کنید. تنظیمات شما سر جایش می‌ماند.

### ساخت

* **بدون SDK**: `packaging/build.sh` باینری را با `cargo` برای هدف‌های musl کراس‌کامپایل می‌کند
  (لینک با `rust-lld`). سپس بسته‌های ipk (با همان ساختار `ipkg-build`) و APK v3 (با
  `apk mkpkg`) را می‌سازد و ترجمه‌ها را با `po2lmo` کامپایل می‌کند. خروجی در `dist/` قرار
  می‌گیرد. `ARCHES=all` همهٔ معماری‌ها را می‌سازد و `packaging/test.sh` بسته‌ها را بررسی می‌کند.
* **با SDK یا buildroot اوپن‌وی‌آرتی**: این مخزن را به‌عنوان feed اضافه کنید
  (`src-git passwall2rs https://github.com/ParsaKSH/openwrt-passwall-rust.git`) و
  `luci-app-passwall2-rs` را از منوی LuCI → Applications انتخاب کنید. این روش از `rust/host`
  مخزن packages و `luci.mk` استاندارد استفاده می‌کند و MIPS را هم پوشش می‌دهد.
* با هر تگ `v*`، گردش‌کار GitHub همهٔ بسته‌ها را می‌سازد و به Release اضافه می‌کند.

مجوز: GPL-3.0-only، مانند PassWall 2 اصلی.

</div>
