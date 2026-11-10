import io
import tarfile
import tempfile
import zipfile
from pathlib import Path

from src.core.archive_utils import contains_supported_source_files, expand_nested_source_archives, extract_archive


def test_expand_nested_source_archives_extracts_src_tarball():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        build = root / "build"
        build.mkdir(parents=True, exist_ok=True)
        archive_path = build / "src.tar.gz"
        payload = b"<?php echo 'ok';"

        with tarfile.open(archive_path, "w:gz") as archive:
            info = tarfile.TarInfo("src/index.php")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))

        expanded = expand_nested_source_archives(root)

        assert expanded
        assert contains_supported_source_files(root)
        assert (build / "src" / "src" / "index.php").exists()


def test_extract_archive_supports_standard_zip():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        archive_path = root / "sample.zip"
        destination = root / "out"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("project/app.py", "print('ok')\n")

        extract_archive(archive_path, destination)

        assert (destination / "project" / "app.py").exists()
