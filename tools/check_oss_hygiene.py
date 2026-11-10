# -*- coding: utf-8 -*-
"""开源卫生门禁：干净 clone 不该带开发机路径、硬编码凭据或过程文档。

CI 直接跑这个脚本，不依赖第三方 secret-scan action（避免外网/授权依赖）。
只读，不修改任何文件；发现违规逐条打印并返回非零。

用法:
    python tools/check_oss_hygiene.py
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 本机绝对路径：只匹配「具体开发机」痕迹，不误伤 `D:/Users/...` 这类
# 说明性示例和 `D:\Users\x\Foo.java:118` 这类测试用的非法路径字面量。
ABS_PATH_RES = [
    re.compile(r"[A-Za-z]:[/\\]+Users[/\\]+dell", re.I),
    re.compile(r"[A-Za-z]:[/\\]+sanjio-knowledge[/\\]+", re.I),
    re.compile(r"Desktop[/\\]+SDL[/\\]+", re.I),
    re.compile(r"[A-Za-z]:[/\\]+WorkBuddy", re.I),
]
# 已知凭据前缀 / 私钥头：无论采用哪种赋值形式都算违规
KNOWN_SECRET = re.compile(
    r"(?:sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")
# 同时覆盖 key = "..."、"key": "..." 与 key: "..."；值里含点号 / 斜杠也算
CRED_ASSIGN = re.compile(
    r"(?i)\b(?:token|api[_-]?key|secret|password|passwd|access[_-]?key|credential)\b"
    r"\s*[:=]\s*[\"']([^\"']{12,})[\"']")
CRED_SAFE = ("${", "example", "placeholder", "your_", "test", "fake", "dummy",
             "changeme", "redacted", "not-a-real", "<", "offline", "canary", "%")
# 内部过程标识：文件名里的 task 编号、docs/task 路径、托管工具品牌、悬空 issue 引用
INTERNAL_TASK_NAME = re.compile(r"task[_-]?\d{2,}", re.I)
INTERNAL_TASK_TEXT = re.compile(r"\btask[ _-]?\d{2,}\b", re.I)
INTERNAL_TASK_PATH = re.compile(r"docs/task\d+", re.I)
INTERNAL_TOOL = re.compile(r"WorkBuddy\s+(?:沙箱|运行时|外壳|sandbox)", re.I)
SELF_DISCLOSURE = re.compile(
    r"用户(?:批准|拍板|确认|要求|决策|明确)|助手(?:不擅自|倾向|自行)|"
    r"已拍板|待拍板|不擅自|filter-repo|内部记忆")
AUTOLINK = re.compile(r"(?<![\w&])#\d{3}[a-z]?\b(?!;)")
INTERNAL_PREFIXES = (".workbuddy-ai/", ".workbuddy/", "data/app.db")
# 必须存在且不得被 .gitignore 命中的文件。命中 ignore 意味着「工作区里有、发布产物里没有」——
# 这类缺口在本机完全看不出来，只在干净 clone 里炸（CI 报 FileNotFoundError）。
REQUIRED_TRACKED = (
    "data/java_sec_code_truth_v2.csv",
    "data/owasp_shards/shards/mini.json",
    "README.md",
    "README_zh.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "config/config.example.yaml",
    "config/run_profiles.yaml",
    "tools/check_oss_hygiene.py",
    "tools/export_clean_snapshot.py",
    "scripts/fetch_tools.py",
    "scripts/launch/launch_stack.py",
    "scripts/launch/launch_java_quote.py",
    "scripts/launch/start_dev.ps1",
    "frontend/package.json",
    "frontend/package-lock.json",
    "probe-java/pom.xml",
)
TEXT_EXT = ("", ".py", ".md", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini",
            ".vue", ".ts", ".js", ".sh", ".cmd", ".bat", ".ql", ".java", ".xml")


def _tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True)
    return [p.decode("utf-8", "replace") for p in out.stdout.split(b"\0") if p]


def _pending() -> list[str]:
    """尚未进索引、但 `git add -A` 会收进去的文件。

    2026-11-06：旧门禁只扫 tracked，当轮新增的 README / docs / 测试 / 配置 /
    issue 模板全部绕过检查；发布时它们同样是干净 clone 的一部分。改为一并扫描，
    已忽略的运行时产物（app.db、logs、.pytest_tmp_*）不在此列。
    """
    out = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True)
    return [p.decode("utf-8", "replace") for p in out.stdout.split(b"\0") if p]


def _ignored_paths(paths: list[str]) -> list[str]:
    """返回被 .gitignore 规则命中的路径。

    `--no-index` 让它只看规则、不看索引状态。用途：导出面里的文件如果被 ignore
    规则命中，那么在干净快照目录里执行 `git add -A` 时会被跳过 —— 文件明明在
    分发清单里，却进不了初始提交，公开仓库就会缺文件。
    """
    if not paths:
        return []
    payload = "\n".join(p.replace("\\", "/") for p in paths).encode("utf-8")
    out = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"],
                         cwd=ROOT, input=payload, capture_output=True)
    return [p for p in out.stdout.decode("utf-8", "replace").split("\n") if p]


def _syntax_errors(files: list[str]) -> list[tuple[str, str]]:
    """找出无法编译的 Python 文件。

    分发面里的 .py 必须是可编译的：内容层的正则检查读得懂坏文件，
    不会报错，损坏会一路带到公开仓库，直到 CI 编译阶段才炸。
    """
    bad: list[tuple[str, str]] = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        path = os.path.join(ROOT, rel.replace("/", os.sep))
        try:
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        try:
            compile(src, path, "exec")
        except SyntaxError as exc:
            bad.append((rel, "line %s: %s" % (exc.lineno, exc.msg)))
    return bad


# 根目录白名单：只允许这些条目。新增要么归入其中之一，要么先想清楚该放哪。
# 历史上出现过 config/ 与 configs/ 两个只差一个字母的目录、5 个 launcher 散在根上、
# testfiles/ 与 tools/testfiles/ 两份历史拷贝 —— 根目录一旦失控，新用户第一眼就放弃。
ROOT_ALLOWED_ENTRIES = frozenset({
    # 文档与治理
    "README.md", "README_zh.md", "LICENSE", "NOTICE", "CHANGELOG.md",
    "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "CONTRIBUTING_zh.md", "SECURITY.md",
    # 构建与依赖
    "pyproject.toml", "requirements.txt", "uv.lock", "sbom.json",
    ".env.example", ".gitignore", ".gitattributes",
    # 目录
    ".github", "config", "data", "docs", "frontend", "probe-java",
    "scripts", "src", "tests", "tools",
})


def _root_entry_violations(files: list[str]) -> list[str]:
    """分发面根目录出现白名单外的条目即违规。

    只看分发面，不看工作区磁盘：本机运行时产物（日志、logs/、output/、本机
    config.yaml、overview.md 等）都已被 .gitignore 排除，不进分发面，不该让门禁失败。
    顶层目录从文件路径的首段推导 —— 目录本身不是文件，不在 files 里。
    """
    bad = []
    for rel in files:
        if "/" in rel:
            continue
        if rel not in ROOT_ALLOWED_ENTRIES:
            bad.append(rel)
    top_dirs = {rel.split("/", 1)[0] for rel in files if "/" in rel}
    for d in sorted(top_dirs):
        if d not in ROOT_ALLOWED_ENTRIES:
            bad.append(d + "/")
    return bad


def _local_import_gaps(files: list[str]) -> list[tuple[str, str]]:
    """找出「导出面代码 import 了、但没随仓库分发」的本地模块。

    干净 clone 里这类缺口表现为 ImportError：CI 直接红、外部用户 clone 后跑不起来。
    只看内容层的卫生规则发现不了，必须做一次依赖闭包检查。
    返回 [(缺失模块名, 首个引用它的文件), ...]。
    """
    mods: set[str] = set()
    pkgs: set[str] = set()
    for rel in files:
        if not rel.endswith(".py"):
            continue
        mod = rel[:-3].replace("/", ".")
        if mod.endswith(".__init__"):
            mod = mod[: -len(".__init__")]
        mods.add(mod)
        d = os.path.dirname(rel)
        while d:
            pkgs.add(d.replace("/", "."))
            d = os.path.dirname(d)
    # 顶层脚本的「裸名 import」：测试常把 tools/ 塞进 sys.path 后 `import xxx`，
    # 这类引用不带包前缀，靠上面的规则查不到，单独按文件名匹配。
    export_set = set(files)
    top_scripts: dict[str, str] = {}
    for base in ("tools", "scripts"):
        d = os.path.join(ROOT, base)
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if fn.endswith(".py") and not fn.startswith("__"):
                top_scripts.setdefault(fn[:-3], base + "/" + fn)
    gaps: dict[str, str] = {}
    for rel in files:
        if not rel.endswith(".py"):
            continue
        path = os.path.join(ROOT, rel.replace("/", os.sep))
        try:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module:
                    continue
                targets = [node.module]
            for t in targets:
                if "." not in t and t in top_scripts and top_scripts[t] not in export_set:
                    gaps.setdefault(t, rel)
                    continue
                if t.split(".")[0] not in ("src", "tools", "scripts"):
                    continue
                if t in mods or t in pkgs:
                    continue
                if any(m.startswith(t + ".") for m in mods):
                    continue
                gaps.setdefault(t, rel)
    return sorted(gaps.items())


def main() -> int:
    tracked = _tracked()
    pending = _pending()
    # 与 export_clean_snapshot.py 的 candidates() 同口径：只看磁盘上真实存在的文件。
    # 否则文件移动后 git ls-files 里的旧路径会被当成待检查项，产生假违规。
    files = [f for f in dict.fromkeys(tracked + pending)
             if os.path.isfile(os.path.join(ROOT, f.replace('/', os.sep)))]
    problems: list[str] = []

    for rel in files:
        if rel.startswith(INTERNAL_PREFIXES) or rel == "data/app.db":
            problems.append("internal/runtime file is tracked: %s" % rel)
        if INTERNAL_TASK_NAME.search(os.path.basename(rel)):
            problems.append("internal task id in filename: %s" % rel)
        ext = os.path.splitext(rel)[1].lower()
        if ext not in TEXT_EXT:
            continue
        path = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            # 编码损坏在公开仓库里表现为乱码，且内容层规则会因读不出而全部跳过
            problems.append("not valid utf-8: %s" % rel)
            continue
        except OSError:
            continue
        if "\ufffd" in text:
            problems.append("replacement char (corrupted text): %s" % rel)
        # 本脚本自身用正则描述模式，跳过以防自匹配
        if rel.replace("\\", "/") == "tools/check_oss_hygiene.py":
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if KNOWN_SECRET.search(line):
                problems.append("known secret prefix: %s:%d" % (rel, i))
            m = CRED_ASSIGN.search(line)
            if m:
                val = m.group(1)
                looks_real = (not any(k in val.lower() for k in CRED_SAFE)
                              and not any(k in line.lower() for k in
                                          ("os.environ", "getenv", "re.compile",
                                           "pattern", "regex"))
                              and re.search(r"[0-9]", val))
                if looks_real:
                    problems.append("hardcoded credential: %s:%d" % (rel, i))
            if INTERNAL_TASK_PATH.search(line):
                problems.append("internal task path: %s:%d" % (rel, i))
            if INTERNAL_TASK_TEXT.search(line):
                problems.append("internal tracking id in text: %s:%d" % (rel, i))
            if SELF_DISCLOSURE.search(line):
                problems.append("development-process self-disclosure: %s:%d" % (rel, i))
            if INTERNAL_TOOL.search(line):
                problems.append("internal tool reference: %s:%d" % (rel, i))
            if ext == ".md" and AUTOLINK.search(line):
                problems.append("dangling issue autolink: %s:%d" % (rel, i))
            if any(p.search(line) for p in ABS_PATH_RES):
                problems.append("local absolute path: %s:%d" % (rel, i))

    # 根目录白名单：防止目录再次膨胀或出现同名近似目录
    for name in _root_entry_violations(files):
        problems.append("unexpected root entry (move it or add it to ROOT_ALLOWED_ENTRIES): %s" % name)

    # 分发面里的 Python 文件必须能编译
    for rel, why in _syntax_errors(files):
        problems.append("python syntax error: %s (%s)" % (rel, why))

    # 分发面文件不能被 .gitignore 命中，否则干净快照做初始提交时会漏文件
    for p in _ignored_paths(files):
        problems.append("distributed file is gitignored (git add would skip): %s" % p)

    # 分发面依赖闭包：代码 import 的本地模块必须都在分发面内
    for mod, user in _local_import_gaps(files):
        problems.append("local module not distributed: %s (imported by %s)"
                        % (mod, user))

    # 检查「文件存在且未被忽略」，而不是「已 staged」——发布前索引状态由维护者决定，
    # 门禁只保证 `git add -A && git commit` 之后干净 clone 能拿到这些文件。
    for rel in REQUIRED_TRACKED:
        if not os.path.isfile(os.path.join(ROOT, rel.replace("/", os.sep))):
            problems.append("reproducibility file missing from worktree: %s" % rel)
        elif subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT).returncode == 0:
            problems.append("reproducibility file is gitignored: %s" % rel)

    if problems:
        print("[oss-hygiene] FAIL (%d)" % len(problems))
        for p in problems[:60]:
            print("  - " + p)
        if len(problems) > 60:
            print("  ... %d more" % (len(problems) - 60))
        return 1
    print("[oss-hygiene] OK: %d inspectable files (%d tracked + %d pending add), "
          "no secrets / local paths / internal notes / tracking ids / self-disclosure"
          % (len(files), len(tracked), len(pending)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
