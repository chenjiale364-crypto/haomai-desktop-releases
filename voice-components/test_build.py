import hashlib
import base64
import gzip
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
    def test_provenance_correction_preserves_complete_file_inventory(self):
        root = Path(__file__).with_name("recipes")
        encoded = (root / "indextts-engine.recipe.json.gz").read_bytes()
        recipe = json.loads(gzip.decompress(encoded))
        fixes = json.loads((root / "provenance-fixes.json").read_text())
        before = [(item["path"], item["bytes"], item["sha256"]) for item in recipe["files"]]
        build.apply_provenance_fixes(recipe, build.digest(encoded), fixes)
        build.validate_recipe(recipe)
        self.assertEqual(before, [(item["path"], item["bytes"], item["sha256"]) for item in recipe["files"]])
        marker = next(item for item in recipe["files"] if item["path"] == "python/Lib/EXTERNALLY-MANAGED")
        self.assertEqual(build.digest(base64.b64decode(recipe["embedded"][marker["embedded"]])), marker["sha256"])

    def test_provenance_cannot_change_a_tested_installer_marker(self):
        recipe = {"id": "indextts-engine", "artifacts": {}, "embedded": {}, "files": [{"path": "python/BUILD", "bytes": 1, "sha256": build.digest(b"a")}]}
        fixes = {"schemaVersion": 1, "packages": {"indextts-engine": {"baseRecipeSha256": "reviewed", "installerMetadata": [
            {"path": "python/BUILD", "sha256": build.digest(b"a"), "content": base64.b64encode(b"b").decode()},
        ]}}}
        with self.assertRaisesRegex(ValueError, "differs"):
            build.apply_provenance_fixes(recipe, "reviewed", fixes)

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
