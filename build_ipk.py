#!/usr/bin/env python3
"""build_ipk.py — Build all zapret-gui packages (cross-platform)

Targets:
  1. zapret-gui-keenetic.ipk  — Entware / Keenetic (opkg)
  2. zapret-gui-openwrt.ipk   — OpenWRT ≤24.05 (opkg)
  3. zapret-gui-openwrt.apk   — OpenWRT 24.10+/25.x (apk-tools 3)
  4. zapret-gui-linux.tar.gz  — universal Linux archive

Usage:
  python build_ipk.py              # build all
  python build_ipk.py entware      # only Entware/Keenetic
  python build_ipk.py openwrt      # only OpenWRT ipk + apk
  python build_ipk.py linux        # only Linux tar.gz
"""

import os
import re
import shutil
import hashlib
import tarfile
import subprocess
import sys

PKG_NAME = "zapret-gui"
BUILD_DIR = "build"
DIST_DIR = "dist"

APP_DIRS = ["api", "core", "config", "web", "catalogs", "data", "import", "vendor", "tests"]


def get_version():
    with open("core/version.py", encoding="utf-8") as f:
        m = re.search(r'GUI_VERSION\s*=\s*"([^"]+)"', f.read())
        if not m:
            raise RuntimeError("GUI_VERSION not found in core/version.py")
        return m.group(1)


def make_tar_gz(source_dir, output_path):
    with tarfile.open(output_path, "w:gz") as tar:
        for item in sorted(os.listdir(source_dir)):
            path = os.path.join(source_dir, item)
            tar.add(path, arcname=item)


def clean_build():
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    os.makedirs(DIST_DIR, exist_ok=True)


def prepare_data_entware(data_dir):
    """Prepare data tree for Entware/Keenetic (/opt/ prefix)."""
    dest_app = "/opt/share/zapret-gui"
    dest_config = "/opt/etc/zapret-gui"
    dest_initd = "/opt/etc/init.d"

    for d in [dest_app, dest_config, dest_initd, "/opt/var/log", "/opt/bin"]:
        os.makedirs(os.path.join(data_dir, d.lstrip("/")), exist_ok=True)

    shutil.copy2("app.py", os.path.join(data_dir, dest_app.lstrip("/"), "app.py"))
    for d in APP_DIRS:
        if os.path.isdir(d):
            shutil.copytree(d, os.path.join(data_dir, dest_app.lstrip("/"), d), dirs_exist_ok=True)

    # Clean pycache
    for root, dirs, files in os.walk(data_dir):
        for d in dirs[:]:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))
                dirs.remove(d)
        for f in files:
            if f.endswith((".pyc", ".pyo")) or f == ".DS_Store":
                os.remove(os.path.join(root, f))

    # Init script
    shutil.copy2("packaging/entware/S99zapret-gui",
                 os.path.join(data_dir, dest_initd.lstrip("/"), "S99zapret-gui"))
    # CLI wrapper
    shutil.copy2("packaging/entware/zapret-gui-cli",
                 os.path.join(data_dir, "opt/bin/zapret-gui"))

    # Create runtime dirs
    os.makedirs(os.path.join(data_dir, dest_app.lstrip("/"), "init.d"), exist_ok=True)
    os.makedirs(os.path.join(data_dir, dest_app.lstrip("/"), "lists"), exist_ok=True)

    return dest_app, dest_config


def prepare_data_openwrt(data_dir):
    """Prepare data tree for OpenWRT (/usr/ and /etc/ prefix)."""
    dest_app = "/usr/share/zapret-gui"
    dest_config = "/etc/zapret-gui"

    for d in [dest_app, dest_config, "/etc/init.d", "/usr/bin"]:
        os.makedirs(os.path.join(data_dir, d.lstrip("/")), exist_ok=True)

    shutil.copy2("app.py", os.path.join(data_dir, dest_app.lstrip("/"), "app.py"))
    for d in APP_DIRS:
        if os.path.isdir(d):
            shutil.copytree(d, os.path.join(data_dir, dest_app.lstrip("/"), d), dirs_exist_ok=True)

    for root, dirs, files in os.walk(data_dir):
        for d in dirs[:]:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d))
                dirs.remove(d)
        for f in files:
            if f.endswith((".pyc", ".pyo")) or f == ".DS_Store":
                os.remove(os.path.join(root, f))

    shutil.copy2("packaging/openwrt/zapret-gui.init",
                 os.path.join(data_dir, "etc/init.d/zapret-gui"))
    shutil.copy2("packaging/openwrt/zapret-gui-cli",
                 os.path.join(data_dir, "usr/bin/zapret-gui"))

    os.makedirs(os.path.join(data_dir, dest_app.lstrip("/"), "init.d"), exist_ok=True)
    os.makedirs(os.path.join(data_dir, dest_app.lstrip("/"), "lists"), exist_ok=True)

    return dest_app, dest_config


def prepare_control(control_dir, platform, version, release, data_size_kb):
    """Prepare control files with version and size substitution."""
    os.makedirs(control_dir, exist_ok=True)

    if platform == "entware":
        src = "packaging/entware"
    else:
        src = "packaging/openwrt"

    for f in ["control", "postinst", "prerm", "conffiles"]:
        shutil.copy2(os.path.join(src, f), os.path.join(control_dir, f))

    with open(os.path.join(control_dir, "control"), encoding="utf-8") as f:
        content = f.read()
    content = content.replace("@VERSION@", f"{version}-{release}")
    content = content.replace("@SIZE@", str(data_size_kb))
    with open(os.path.join(control_dir, "control"), "w", encoding="utf-8") as f:
        f.write(content)


def calc_data_size(data_dir):
    total = 0
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            total += os.path.getsize(os.path.join(root, f))
    return int(total / 1024)


def build_ipk(data_dir, control_dir, output_path):
    """Build .ipk package (tar of debian-binary + control.tar.gz + data.tar.gz)."""
    ipk_dir = os.path.join(BUILD_DIR, "ipk")
    os.makedirs(ipk_dir, exist_ok=True)

    with open(os.path.join(ipk_dir, "debian-binary"), "w") as f:
        f.write("2.0")

    make_tar_gz(control_dir, os.path.join(ipk_dir, "control.tar.gz"))
    make_tar_gz(data_dir, os.path.join(ipk_dir, "data.tar.gz"))

    if os.path.exists(output_path):
        os.remove(output_path)

    with tarfile.open(output_path, "w") as ipk:
        ipk.add(os.path.join(ipk_dir, "debian-binary"), arcname="debian-binary")
        ipk.add(os.path.join(ipk_dir, "control.tar.gz"), arcname="control.tar.gz")
        ipk.add(os.path.join(ipk_dir, "data.tar.gz"), arcname="data.tar.gz")


def report(path):
    size_mb = round(os.path.getsize(path) / (1024 * 1024), 2)
    sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
    print(f"  {os.path.basename(path)}: {size_mb} MB, SHA256: {sha[:16]}...")
    return sha


def build_entware(version, release):
    """Build Entware/Keenetic ipk."""
    print("=== Entware/Keenetic ipk ===")
    clean_build()

    data_dir = os.path.join(BUILD_DIR, "data")
    control_dir = os.path.join(BUILD_DIR, "control")

    prepare_data_entware(data_dir)
    size_kb = calc_data_size(data_dir)
    prepare_control(control_dir, "entware", version, release, size_kb)

    out = os.path.join(DIST_DIR, f"{PKG_NAME}-keenetic.ipk")
    build_ipk(data_dir, control_dir, out)
    report(out)

    # Also copy as entware
    entware_out = os.path.join(DIST_DIR, f"{PKG_NAME}-entware.ipk")
    shutil.copy2(out, entware_out)
    print(f"  {os.path.basename(entware_out)}: copy of keenetic")
    print()


def build_openwrt_ipk(version, release):
    """Build OpenWRT ipk (opkg)."""
    print("=== OpenWRT ipk ===")
    clean_build()

    data_dir = os.path.join(BUILD_DIR, "data")
    control_dir = os.path.join(BUILD_DIR, "control")

    prepare_data_openwrt(data_dir)
    size_kb = calc_data_size(data_dir)
    prepare_control(control_dir, "openwrt", version, release, size_kb)

    out = os.path.join(DIST_DIR, f"{PKG_NAME}-openwrt.ipk")
    build_ipk(data_dir, control_dir, out)
    report(out)
    print()


def build_linux_archive(version):
    """Build universal Linux tar.gz."""
    print("=== Linux tar.gz ===")
    out = os.path.join(DIST_DIR, f"{PKG_NAME}-{version}-linux.tar.gz")

    exclude_dirs = {".git", "build", "dist", "__pycache__", ".github"}
    exclude_files = {".DS_Store", ".gitignore"}

    with tarfile.open(out, "w:gz") as tar:
        for item in sorted(os.listdir(".")):
            if item in exclude_dirs or item in exclude_files:
                continue
            if item.endswith((".pyc", ".pyo")):
                continue
            tar.add(item)

    report(out)
    print()


def main():
    version = get_version()
    release = "1"
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    print(f"Building {PKG_NAME} v{version}-{release}")
    print(f"Target: {target}")
    print()

    if target in ("all", "entware"):
        build_entware(version, release)

    if target in ("all", "openwrt"):
        build_openwrt_ipk(version, release)

    if target in ("all", "linux"):
        build_linux_archive(version)

    print("=== All done ===")
    for f in sorted(os.listdir(DIST_DIR)):
        fp = os.path.join(DIST_DIR, f)
        if os.path.isfile(fp):
            sz = round(os.path.getsize(fp) / 1024, 1)
            print(f"  {f}: {sz} KB")


if __name__ == "__main__":
    main()
