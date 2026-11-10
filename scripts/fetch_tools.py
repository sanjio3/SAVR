"""下载第三方二进制工具（开源准备：第三方二进制不入库）。

背景（2026-10-27）：仓库曾把 nuclei/ffuf/feroxbuster/ysoserial 共 225MB 直接入库，
既撑大仓库又涉及再分发合规。现改为「按需下载」：

    python scripts/fetch_tools.py --dest D:/SAVR-tools
    set SAST_AI_TOOLS_DIR=D:/SAVR-tools   (Windows)
    export SAST_AI_TOOLS_DIR=/opt/SAVR-tools  (Linux/macOS)

工具缺失时的行为（已由 src/core/tool_paths.py 保证）：
  * ysoserial 缺失 → 反序列化 payload 只给生成指令，不伪造 payload（不阻断）
  * nuclei/ffuf/feroxbuster 缺失 → 返回 None，调用方按 skipped 处理（当前无调用方）

安全提示：默认从各项目官方 GitHub Releases 下载。下载后会打印 SHA256；
生产环境请用 --sha256 指定已知哈希做校验。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import urllib.request

# name -> (URL, 目标文件名)
TOOLS = {
    "ysoserial": (
        "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar",
        "ysoserial-all.jar",
    ),
    "nuclei": (
        "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_windows_amd64.zip",
        "nuclei.exe",
    ),
    "ffuf": (
        "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_windows_amd64.zip",
        "ffuf.exe",
    ),
    "feroxbuster": (
        "https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-windows-feroxbuster.exe.zip",
        "feroxbuster.exe",
    ),
}


# Bundle archives are unpacked as a directory tree instead of a single binary.
# CodeQL ships its CLI together with the query packs, so the tree must be kept;
# tool_paths.find_codeql() looks for <dest>/codeql/codeql afterwards.
def _codeql_platform() -> str:
    if os.name == "nt":
        return "win64"
    if sys.platform == "darwin":
        return "osx64"
    return "linux64"


ARCHIVE_TOOLS = {
    "codeql": (
        "https://github.com/github/codeql-action/releases/latest/download/"
        "codeql-bundle-%s.tar.gz" % _codeql_platform(),
        "codeql",
    ),
}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: str) -> None:
    tmp = dest + ".part"
    with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    os.replace(tmp, dest)


def _unpack_archive(url: str, dest: str) -> None:
    """Download a .tar.gz bundle and unpack it into dest, keeping the tree."""
    import tarfile
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        archive = os.path.join(td, "bundle.tar.gz")
        _download(url, archive)
        print("[ok  ] archive sha256=%s" % _sha256(archive))
        with tarfile.open(archive, "r:gz") as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:  # pragma: no cover - Python < 3.12
                tf.extractall(dest)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", default=os.environ.get("SAST_AI_TOOLS_DIR", ""),
                    help="下载目录（默认取 SAST_AI_TOOLS_DIR）")
    ap.add_argument("--only", default="", help="只下载指定工具（逗号分隔）")
    ap.add_argument("--sha256", default="", help="期望哈希（name=hash,name=hash）")
    args = ap.parse_args()

    if not args.dest:
        print("[FATAL] 未指定 --dest，且环境变量 SAST_AI_TOOLS_DIR 为空")
        return 1
    os.makedirs(args.dest, exist_ok=True)
    wanted = {s.strip() for s in args.only.split(",") if s.strip()} or (
        set(TOOLS) | set(ARCHIVE_TOOLS)
    )
    expected = {}
    for pair in (args.sha256 or "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            expected[k.strip()] = v.strip().lower()

    for name, (url, subdir) in ARCHIVE_TOOLS.items():
        if name not in wanted:
            continue
        exe = os.path.join(args.dest, subdir, "codeql.exe" if os.name == "nt" else "codeql")
        if os.path.isfile(exe):
            print("[skip] %s 已存在：%s" % (name, exe))
            continue
        print("[get ] %s ← %s" % (name, url))
        try:
            _unpack_archive(url, args.dest)
        except Exception as exc:  # noqa: BLE001
            print("[fail] %s：%s" % (name, exc))
            continue
        if os.path.isfile(exe):
            print("[ok  ] %s → %s" % (name, exe))
        else:
            print("[warn] 解包后未找到 %s，请检查 bundle 目录结构" % exe)

    for name, (url, filename) in TOOLS.items():
        if name not in wanted:
            continue
        target = os.path.join(args.dest, filename)
        if os.path.isfile(target):
            print("[skip] %s 已存在：%s" % (name, target))
            continue
        print("[get ] %s ← %s" % (name, url))
        try:
            if filename.endswith(".zip"):
                import tempfile
                import zipfile
                with tempfile.TemporaryDirectory() as td:
                    zp = os.path.join(td, "pkg.zip")
                    _download(url, zp)
                    with zipfile.ZipFile(zp) as zf:
                        zf.extractall(td)
                    found = ""
                    for root, _dirs, files in os.walk(td):
                        for fn in files:
                            if fn == filename:
                                found = os.path.join(root, fn)
                    if not found:
                        print("[warn] 压缩包里没有 %s，请手动检查" % filename)
                        continue
                    shutil.copy2(found, target)
            else:
                _download(url, target)
        except Exception as exc:  # noqa: BLE001
            print("[fail] %s：%s" % (name, exc))
            continue
        digest = _sha256(target)
        print("[ok  ] %s sha256=%s" % (target, digest))
        if name in expected and expected[name] != digest:
            print("[WARN] 哈希不匹配：期望 %s，实际 %s" % (expected[name], digest))
            return 2

    print("\n完成。设置环境变量后生效：")
    print("  Windows: set SAST_AI_TOOLS_DIR=%s" % args.dest)
    print("  Linux/macOS: export SAST_AI_TOOLS_DIR=%s" % args.dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
