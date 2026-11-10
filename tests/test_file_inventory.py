import tempfile
import unittest
from pathlib import Path

from src.core.file_inventory import iter_files
from src.core.scanner import FileScanner


class FileInventoryTests(unittest.TestCase):
    def test_iter_files_skips_runtime_and_output_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "output").mkdir()
            (root / "__pycache__").mkdir()
            (root / ".d2-node-ssrf-test").mkdir()

            (root / "src" / "keep.py").write_text("print('ok')", encoding="utf-8")
            (root / "output" / "drop.py").write_text("print('no')", encoding="utf-8")
            (root / "__pycache__" / "drop.py").write_text("print('no')", encoding="utf-8")
            (root / ".d2-node-ssrf-test" / "drop.py").write_text("print('no')", encoding="utf-8")

            discovered = sorted(path.relative_to(root).as_posix() for path in iter_files(root, {".py"}))
            self.assertEqual(discovered, ["src/keep.py"])

    def test_scanner_ignores_output_tree(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app").mkdir()
            (root / "output").mkdir()
            (root / "app" / "main.py").write_text("print('ok')", encoding="utf-8")
            (root / "output" / "report.py").write_text("print('noise')", encoding="utf-8")

            scanner = FileScanner(str(root), languages=["python"])
            files = scanner.scan(show_progress=False)

            self.assertEqual(len(files), 1)
            self.assertEqual(Path(files[0]["rel_path"]).as_posix(), "app/main.py")


if __name__ == "__main__":
    unittest.main()
