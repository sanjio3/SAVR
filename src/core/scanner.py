"""
Source file scanner shared by static-analysis stages.
"""
from pathlib import Path
from typing import Dict, List, Optional
import logging

from .config import config
from .file_inventory import iter_files, load_skip_dirs

logger = logging.getLogger(__name__)


LANGUAGE_EXTENSIONS = {
    "java": [".java", ".kt", ".scala", ".jsp", ".jspx"],
    "python": [".py", ".pyw", ".pyx"],
    "javascript": [".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue"],
    "go": [".go"],
    "php": [".php", ".phtml"],
    "c": [".c", ".h", ".cpp", ".hpp", ".cc"],
    "ruby": [".rb", ".erb"],
    "rust": [".rs"],
    "csharp": [".cs"],
    "sql": [".sql"],
    "yaml": [".yaml", ".yml"],
    "xml": [".xml", ".xhtml", ".xsd"],
    "properties": [".properties", ".conf", ".config"],
    "shell": [".sh", ".bash"],
    # （th:utext）在模板里、不在 Java 里。此前 .html 不在白名单 → 模板从不进扫描集 →
    # java_rules.yaml 里写了 th:utext pattern 也永不命中。
    # 风险：放开 .html 会把前端静态资源全量拉进扫描集、撑爆 A2 的 per-file LLM。
    # 故 FileScanner 对 template 组额外做「内容判定」：必须含模板引擎标记才收录（见
    "template": [".html", ".htm", ".ftl", ".vm"],
}

# 模板引擎标记：出现才认为是「会被服务端渲染的模板」而非普通静态页。
# 只看前 4000 字符（Thymeleaf 的 xmlns:th 通常就在 <html> 标签上）。
_TEMPLATE_ENGINE_MARKERS = ("xmlns:th", "th:", "data-th-", "[th:", "freemarker", "<#")
_TEMPLATE_SNIFF_CHARS = 4000


def _is_engine_template(content: str) -> bool:
    """内容判定：是否是被模板引擎渲染的模板（而非纯静态 HTML）。

    这是放开 .html 后的防噪声闸门。宁可漏收一个模板，也不能把 dist/ 里几百个静态页
    灌进 A2 的 per-file LLM。
    """
    if not content:
        return False
    head = content[:_TEMPLATE_SNIFF_CHARS]
    return any(marker in head for marker in _TEMPLATE_ENGINE_MARKERS)

DEFAULT_SKIP_DIRS = sorted(load_skip_dirs())


class FileScanner:
    """Multi-language source file scanner."""

    def __init__(
        self,
        target_path: str,
        extensions: Optional[List[str]] = None,
        languages: Optional[List[str]] = None,
        skip_dirs: Optional[List[str]] = None,
    ):
        self.target_path = Path(target_path)
        if extensions:
            self.extensions = {ext.lower() for ext in extensions}
        elif languages:
            self.extensions = set()
            for lang in languages:
                self.extensions.update(LANGUAGE_EXTENSIONS.get(lang, []))
        else:
            self.extensions = {
                ext
                for extension_group in LANGUAGE_EXTENSIONS.values()
                for ext in extension_group
            }

        self.skip_dirs = load_skip_dirs(skip_dirs)
        self.max_file_size = int(config.get("scan.max_file_size", 500)) * 1024
        self.stats = {
            "total_files": 0,
            "by_language": {},
            "skipped_dirs": 0,
            "skipped_large": 0,
            "skipped_error": 0,
        }

    def scan(self, show_progress: bool = True) -> List[Dict[str, str]]:
        files = []
        if not self.target_path.exists():
            logger.error("Target path does not exist: %s", self.target_path)
            return files

        all_files = [
            filepath
            for filepath in iter_files(self.target_path, None, self.skip_dirs)
            if self._should_include_source_file(filepath)
        ]
        total = len(all_files)
        logger.info("Found %s files to scan", total)

        for index, filepath in enumerate(all_files, start=1):
            if show_progress and index % 10 == 0:
                logger.info("Processing: %s/%s (%s%%)", index, total, (100 * index // total) if total else 100)

            try:
                file_size = filepath.stat().st_size
            except Exception as exc:
                logger.warning("Error checking file size: %s - %s", filepath, exc)
                self.stats["skipped_error"] += 1
                continue

            if file_size > self.max_file_size:
                logger.warning("Skipping large file: %s", filepath)
                self.stats["skipped_large"] += 1
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                rel_path = filepath.relative_to(self.target_path)
                language = self._detect_language(filepath.name)
                # 模板层内容闸门：.html/.htm 只有确属模板引擎模板才收录，
                # 否则前端静态资源/构建产物会把 A2 的 per-file LLM 撑爆。
                if language == "template" and not _is_engine_template(content):
                    self.stats["skipped_static_html"] = self.stats.get("skipped_static_html", 0) + 1
                    continue
                self.stats["total_files"] += 1
                self.stats["by_language"][language] = self.stats["by_language"].get(language, 0) + 1
                files.append(
                    {
                        "path": str(filepath),
                        "name": filepath.name,
                        "rel_path": str(rel_path),
                        "content": content,
                        "language": language,
                        "size": file_size,
                    }
                )
            except Exception as exc:
                logger.warning("Error reading file: %s - %s", filepath, exc)
                self.stats["skipped_error"] += 1

        self._print_stats()
        return files

    def _detect_language(self, filename: str) -> str:
        lowered_name = str(filename or "").lower()
        if lowered_name == "dockerfile" or lowered_name.startswith("dockerfile."):
            return "dockerfile"
        ext = Path(filename).suffix.lower()
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                return lang
        return "unknown"

    def _should_include_source_file(self, filepath: Path) -> bool:
        lowered_name = filepath.name.lower()
        if lowered_name == "dockerfile" or lowered_name.startswith("dockerfile."):
            return True
        return filepath.suffix.lower() in self.extensions

    def _print_stats(self):
        logger.info("=" * 50)
        logger.info("Scan Statistics:")
        logger.info("  Total files: %s", self.stats["total_files"])
        logger.info("  Skipped (large): %s", self.stats["skipped_large"])
        logger.info("  Skipped (error): %s", self.stats["skipped_error"])
        logger.info("  By language:")
        for lang, count in sorted(self.stats["by_language"].items(), key=lambda item: -item[1]):
            logger.info("    %s: %s", lang, count)
        logger.info("=" * 50)

    def get_file_content(self, filepath: str) -> Optional[str]:
        try:
            return Path(filepath).read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.error("Error reading file %s: %s", filepath, exc)
            return None

    @classmethod
    def get_supported_languages(cls) -> List[str]:
        return list(LANGUAGE_EXTENSIONS.keys())

    @classmethod
    def get_language_extensions(cls, language: str) -> List[str]:
        return LANGUAGE_EXTENSIONS.get(language, [])
