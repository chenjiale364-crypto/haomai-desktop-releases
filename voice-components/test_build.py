import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("cloud_build", Path(__file__).with_name("build.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class CloudBuildTests(unittest.TestCase):
    def test_windows_paths_are_bounded(self):
        for name in ("../escape", "/absolute", "a\\b", "CON.txt", "ok/../no", "a. /no", "a:", "a\x00b"):
            self.assertFalse(build.safe_path(name), name)
        self.assertTrue(build.safe_path("python/Lib/site-packages/torch/__init__.py"))

    def test_partitioned_zip_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def closed(file):
                return {"name": file.name, "bytes": file.stat().st_size, "sha256": build.file_digest(file)}
            writer = build.PartsWriter(root, "fixture", closed, limit=128)
            content = bytes(range(256)) * 5
            entry = {"path": "test.bin", "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            with zipfile.ZipFile(writer, "w") as archive:
                build.write_verified(archive, entry, io.BytesIO(content))
            writer.finish_part()
            self.assertGreater(len(writer.parts), 1)
            encoded = b"".join((root / item["name"]).read_bytes() for item in writer.parts)
            with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
                self.assertEqual(archive.read("test.bin"), content)
            self.assertTrue(all(item["bytes"] <= 128 for item in writer.parts))

    def test_mismatched_content_rejected(self):
        entry = {"path": "file.txt", "bytes": 3, "sha256": hashlib.sha256(b"yes").hexdigest()}
        with zipfile.ZipFile(io.BytesIO(), "w") as archive:
            with self.assertRaisesRegex(ValueError, "differs"):
                build.write_verified(archive, entry, io.BytesIO(b"bad"))

    def test_newline_transform_must_match_expected_hash(self):
        entry = {"path": "file.py", "bytes": 3, "sha256": hashlib.sha256(b"a\r\n").hexdigest(), "newlines": "crlf"}
        with zipfile.ZipFile(io.BytesIO(), "w") as archive:
            build.write_verified(archive, entry, io.BytesIO(b"a\n"))

    def test_tar_is_read_without_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "original.tar.gz"
            with tarfile.open(file, "w:gz") as archive:
                item = tarfile.TarInfo("pkg/src/module/file.py"); item.size = 2
                archive.addfile(item, io.BytesIO(b"ok"))
            original = build.OriginalArchive(file, "tar")
            with original.open("module/file.py") as stream: self.assertEqual(stream.read(), b"ok")
            original.close()
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_duplicate_archive_members_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "original.zip"
            with zipfile.ZipFile(file, "w") as archive:
                archive.writestr("a/module.py", "a"); archive.writestr("b/module.py", "b")
            original = build.OriginalArchive(file, "zip")
            with self.assertRaisesRegex(ValueError, "ambiguous"): original.open("module.py")
            original.close()


if __name__ == "__main__":
    unittest.main()
