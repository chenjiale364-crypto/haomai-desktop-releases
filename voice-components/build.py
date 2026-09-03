"""Reconstruct tested Windows components from hash-locked public sources.

No downloaded source, wheel, executable or model is executed. Only this stdlib
builder runs on the hosted Linux runner. Release stays DRAFT until a separate
local verification/signing step. No private signing key is available here.
"""
from __future__ import annotations
import argparse
import base64
from collections import defaultdict
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
import zipfile

REPOSITORY = "chenjiale364-crypto/haomai-desktop-releases"
RELEASE_ID = 381995933
RELEASE_TAG = "voice-components-2.5.0-haomai.1"
PACKAGE_IDS = {"indextts-engine", "indextts-2.5-core", "qwen-emotion", "shared-caption-alignment"}
GIB = 1024 ** 3
CHUNK = 4 * 1024 ** 2
SOURCE_HOSTS = {"files.pythonhosted.org", "download.pytorch.org", "download-r2.pytorch.org", "github.com",
                "codeload.github.com", "raw.githubusercontent.com", "huggingface.co"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_path(name):
    return isinstance(name, str) and 0 < len(name) < 512 and not re.search(r'[\\<>:"|?*\x00-\x1f]', name) and all(
        part and part not in {".", ".."} and not part.endswith((".", " "))
        and not re.match(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part, re.I)
        for part in name.split("/")
    )


def validate_recipe(recipe):
    if recipe.get("schemaVersion") != 1 or recipe.get("id") not in PACKAGE_IDS or recipe.get("version") != "2.5.0-haomai.1":
        raise ValueError("Unexpected component recipe")
    files = recipe.get("files", [])
    if not 0 < len(files) <= 150000 or recipe.get("compatibility") != "indextts-2.5-haomai-1":
        raise ValueError("Invalid component contract")
    seen, total = set(), 0
    for entry in files:
        name = entry.get("path")
        if not safe_path(name) or name.lower() in seen or not re.fullmatch(r"[a-f0-9]{64}", entry.get("sha256", "")):
            raise ValueError("Unsafe or repeated component file")
        if type(entry.get("bytes")) is not int or not 0 <= entry["bytes"] <= 8 * GIB:
            raise ValueError("Unbounded file")
        seen.add(name.lower()); total += entry["bytes"]
        if ("artifact" in entry) == ("embedded" in entry):
            raise ValueError("A file needs one source")
        if "embedded" in entry:
            content = base64.b64decode(recipe["embedded"][entry["embedded"]], validate=True)
            if len(content) > 2 * 1024 ** 2 or len(content) != entry["bytes"] or digest(content) != entry["sha256"]:
                raise ValueError("Overlay integrity mismatch")
        elif entry["artifact"] not in recipe["artifacts"]:
            raise ValueError("Unknown original source")
        if entry.get("newlines") not in {None, "crlf"}:
            raise ValueError("Unknown transform")
    if total != recipe.get("installedBytes") or total > 64 * GIB:
        raise ValueError("Installed byte count mismatch")
    for source in recipe["artifacts"].values():
        parsed = urlparse(source["url"])
        if parsed.scheme != "https" or parsed.hostname not in SOURCE_HOSTS or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Unapproved download source")
        if source.get("kind") not in {"zip", "tar", "file"}:
            raise ValueError("Unknown source archive")
        if source.get("sha256") and not re.fullmatch(r"[a-f0-9]{64}", source["sha256"]):
            raise ValueError("Invalid source hash")
        if not source.get("sha256") and not re.fullmatch(r"https://codeload.github.com/index-tts/index-tts/tar.gz/[0-9a-f]{40}", source["url"]):
            raise ValueError("Unpinned source")


def github(method, path, data=None):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("A scoped GitHub Actions token is required")
    request = Request("https://api.github.com/repos/" + REPOSITORY + path,
                      data=None if data is None else json.dumps(data).encode(), method=method,
                      headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=60) as response:
            body = response.read(10 * 1024 ** 2 + 1)
            if len(body) > 10 * 1024 ** 2: raise RuntimeError("Unexpected GitHub response size")
            return json.loads(body) if body else None
    except HTTPError as error:
        raise RuntimeError(f"GitHub API status {error.code}") from None


def assert_draft():
    release = github("GET", f"/releases/{RELEASE_ID}")
    if release["tag_name"] != RELEASE_TAG or not release["draft"]:
        raise RuntimeError("Refusing to modify a public or different release")
    return release


def upload(file, expected_name=None):
    name, size, hashed = expected_name or file.name, file.stat().st_size, file_digest(file)
    if not re.fullmatch(r"[A-Za-z0-9._+-]+", name): raise ValueError("Unsafe release asset name")
    for attempt in range(3):
        assert_draft()
        assets = github("GET", f"/releases/{RELEASE_ID}/assets?per_page=100")
        matching = [asset for asset in assets if asset["name"] == name]
        if len(matching) > 1: raise RuntimeError("Duplicate release asset")
        if matching:
            asset = matching[0]
            if asset["state"] == "uploaded" and asset["size"] == size and asset.get("digest") == "sha256:" + hashed:
                print(json.dumps({"reusedVerifiedPart": name, "bytes": size}), flush=True)
                return {"name": name, "bytes": size, "sha256": hashed}
            if asset["state"] != "starter" or asset.get("digest") or asset["size"] != size:
                raise RuntimeError(f"Existing complete/different asset preserved: {name}")
            github("DELETE", f"/releases/assets/{asset['id']}")
        connection = http.client.HTTPSConnection("uploads.github.com", timeout=60)
        try:
            connection.putrequest("POST", f"/repos/{REPOSITORY}/releases/{RELEASE_ID}/assets?name={quote(name)}")
            connection.putheader("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
            connection.putheader("Accept", "application/vnd.github+json")
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Content-Length", str(size))
            connection.putheader("User-Agent", "haomai-voice-component-builder")
            connection.endheaders()
            with file.open("rb") as stream:
                while chunk := stream.read(CHUNK): connection.send(chunk)
            response = connection.getresponse()
            body = response.read(1024 ** 2)
            if response.status not in {200, 201}: raise RuntimeError(f"Asset upload status {response.status}")
            asset = json.loads(body)
            if asset.get("state") != "uploaded" or asset.get("size") != size or asset.get("digest") != "sha256:" + hashed:
                raise RuntimeError("Uploaded asset digest mismatch")
            print(json.dumps({"uploaded": name, "bytes": size, "sha256": hashed}), flush=True)
            return {"name": name, "bytes": size, "sha256": hashed}
        except (OSError, http.client.HTTPException, RuntimeError):
            if attempt == 2: raise
            time.sleep(2 * (attempt + 1))
        finally:
            connection.close()
    raise RuntimeError("Asset upload failed")


def download(source, file):
    for attempt in range(3):
        hashed, count = hashlib.sha256(), 0
        try:
            # No GitHub token or other credentials are sent to source publishers.
            with urlopen(Request(source["url"], headers={"User-Agent": "haomai-component-build"}), timeout=60) as response, file.open("xb") as output:
                while chunk := response.read(CHUNK):
                    count += len(chunk)
                    if count > source.get("bytes", 8 * GIB): raise ValueError("Original download exceeded its limit")
                    hashed.update(chunk); output.write(chunk)
            if source.get("bytes") and source["bytes"] != count: raise ValueError("Original download byte mismatch")
            if source.get("sha256") and source["sha256"] != hashed.hexdigest(): raise ValueError("Original download digest mismatch")
            return
        except (OSError, HTTPError, http.client.HTTPException):
            if attempt == 2: raise
            file.unlink(missing_ok=True)  # This exact, newly created cache file only.
            time.sleep(2 * (attempt + 1))


def read_small_asset(asset):
    if asset["size"] > 5 * 1024 ** 2 or asset["state"] != "uploaded": raise ValueError("Invalid build manifest asset")
    connection = http.client.HTTPSConnection("api.github.com", timeout=60)
    try:
        connection.request("GET", f"/repos/{REPOSITORY}/releases/assets/{asset['id']}", headers={
            "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"], "Accept": "application/octet-stream", "User-Agent": "haomai-component-build",
        })
        response = connection.getresponse()
        if response.status == 200:
            data = response.read(5 * 1024 ** 2 + 1)
        elif response.status in {301, 302, 303, 307}:
            location = response.getheader("Location")
            parsed = urlparse(location)
            if parsed.scheme != "https" or parsed.hostname not in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}:
                raise ValueError("Unapproved asset redirect")
            # Do not forward the repository credential to the download CDN.
            with urlopen(location, timeout=60) as download_response:
                data = download_response.read(5 * 1024 ** 2 + 1)
        else: raise RuntimeError(f"Manifest download status {response.status}")
    finally:
        connection.close()
    if len(data) != asset["size"] or "sha256:" + digest(data) != asset["digest"]:
        raise ValueError("Remote build manifest changed")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as archive:
        decoded = archive.read(32 * 1024 ** 2 + 1)
    if len(decoded) > 32 * 1024 ** 2: raise ValueError("Oversized build manifest")
    return json.loads(decoded)


def reuse_complete_package(recipe):
    assets = github("GET", f"/releases/{RELEASE_ID}/assets?per_page=100")
    matches = [item for item in assets if item["name"] == recipe["id"] + ".manifest.json.gz"]
    if not matches: return False
    if len(matches) != 1: raise ValueError("Ambiguous component manifest")
    manifest = read_small_asset(matches[0])
    for key in ("id", "version", "compatibility", "installedBytes"):
        if manifest.get(key) != recipe[key]: raise ValueError("Existing component metadata differs")
    expected_files = [{key: entry[key] for key in ("path", "bytes", "sha256")} for entry in recipe["files"]]
    if manifest.get("files") != expected_files or manifest.get("cloudVerification", {}).get("allFilesMatchTestedRuntime") is not True:
        raise ValueError("Existing component is not the tested payload")
    if not 0 < len(manifest.get("parts", [])) <= 64: raise ValueError("Invalid existing parts")
    for order, part in enumerate(manifest["parts"], 1):
        if part["name"] != f"{recipe['id']}-{recipe['version']}.zip.{order:03d}": raise ValueError("Unexpected existing asset name")
        found = [asset for asset in assets if asset["name"] == part["name"]]
        if len(found) != 1 or found[0]["state"] != "uploaded" or found[0]["size"] != part["bytes"] or found[0].get("digest") != "sha256:" + part["sha256"]:
            raise ValueError("Existing component archive is incomplete")
    print(json.dumps({"reusedCompleteComponent": recipe["id"], "files": len(expected_files), "noRepeatedDownloads": True}), flush=True)
    return True


class OriginalArchive:
    def __init__(self, file, kind):
        self.file, self.kind = file, kind
        self.archive = zipfile.ZipFile(file) if kind == "zip" else tarfile.open(file, "r:*") if kind == "tar" else None
        if kind == "zip": self.names = [entry.filename for entry in self.archive.infolist() if not entry.is_dir()]
        elif kind == "tar": self.names = [entry.name for entry in self.archive.getmembers() if entry.isfile()]
        else: self.names = []

    def open(self, requested=None):
        if self.kind == "file": return self.file.open("rb")
        exact = [name for name in self.names if name == requested]
        found = exact or [name for name in self.names if name.endswith("/" + requested)]
        found = [name for name in found if not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts]
        if len(found) != 1: raise ValueError(f"Original member missing or ambiguous: {requested}")
        return self.archive.open(found[0]) if self.kind == "zip" else self.archive.extractfile(found[0])

    def close(self):
        if self.archive: self.archive.close()


class PartsWriter:
    def __init__(self, root, prefix, on_part, limit=GIB):
        self.root, self.prefix, self.on_part, self.limit = root, prefix, on_part, limit
        self.position, self.current_size = 0, 0
        self.stream = None
        self.parts = []

    def tell(self): return self.position

    def flush(self):
        if self.stream: self.stream.flush()

    def finish_part(self):
        if self.stream:
            self.stream.close(); self.stream = None
            record = self.on_part(self.file)
            self.parts.append(record)

    def write(self, content):
        remaining, count = memoryview(content), len(content)
        while remaining:
            if self.stream is None:
                self.file = self.root / f"{self.prefix}.zip.{len(self.parts) + 1:03d}"
                self.stream = self.file.open("xb"); self.current_size = 0
            length = min(len(remaining), self.limit - self.current_size)
            self.stream.write(remaining[:length])
            self.current_size += length; self.position += length; remaining = remaining[length:]
            if self.current_size == self.limit: self.finish_part()
        return count


def write_verified(archive, entry, source):
    if entry.get("newlines") == "crlf":
        content = source.read(2 * 1024 ** 2 + 1)
        if len(content) > 2 * 1024 ** 2: raise ValueError("Oversized text transform")
        source = io.BytesIO(content.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    info = zipfile.ZipInfo(entry["path"], date_time=(2026, 9, 3, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info._compresslevel = 1
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    hashed, count = hashlib.sha256(), 0
    with archive.open(info, "w", force_zip64=True) as output:
        while chunk := source.read(CHUNK):
            count += len(chunk)
            if count > entry["bytes"]: raise ValueError(f"Original member too large: {entry['path']}")
            hashed.update(chunk); output.write(chunk)
    if count != entry["bytes"] or hashed.hexdigest() != entry["sha256"]:
        raise ValueError(f"File differs from tested runtime: {entry['path']}")


def build(recipe, work):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise RuntimeError("Publishing runs only in the authorized GitHub repository")
    assert_draft()
    if reuse_complete_package(recipe): return
    work.mkdir(parents=True, exist_ok=False)
    cache, assets = work / "cache", work / "assets"
    cache.mkdir(); assets.mkdir()

    def on_part(file):
        record = upload(file)
        file.unlink()  # Only this verified, uploaded build part; preserves disk.
        return record

    writer = PartsWriter(assets, recipe["id"] + "-" + recipe["version"], on_part)
    groups = defaultdict(list)
    for entry in recipe["files"]: groups[entry.get("artifact", "embedded")].append(entry)
    checked = 0
    with zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as archive:
        for source_id in sorted(groups):
            original = None
            if source_id != "embedded":
                source = recipe["artifacts"][source_id]
                file = cache / source_id
                print(json.dumps({"downloadOriginal": source_id, "host": urlparse(source["url"]).hostname, "verifiedFiles": checked}), flush=True)
                download(source, file)
                original = OriginalArchive(file, source["kind"])
            try:
                for entry in groups[source_id]:
                    stream = original.open(entry.get("member")) if original else io.BytesIO(base64.b64decode(recipe["embedded"][entry["embedded"]], validate=True))
                    with stream: write_verified(archive, entry, stream)
                    checked += 1
            finally:
                if original: original.close(); file.unlink()
    writer.finish_part()
    manifest = {key: recipe[key] for key in ("id", "version", "compatibility", "installedBytes")}
    manifest["files"] = [{key: entry[key] for key in ("path", "bytes", "sha256")} for entry in recipe["files"]]
    manifest["parts"] = writer.parts
    manifest["cloudVerification"] = {"allFilesMatchTestedRuntime": True, "verifiedFiles": checked,
                                      "buildCommit": os.environ.get("GITHUB_SHA"), "runId": os.environ.get("GITHUB_RUN_ID")}
    manifest_file = assets / (recipe["id"] + ".manifest.json.gz")
    manifest_file.write_bytes(gzip.compress(json.dumps(manifest, separators=(",", ":")).encode(), mtime=0))
    upload(manifest_file)
    print(json.dumps({"componentComplete": recipe["id"], "files": checked, "parts": len(writer.parts), "releaseStillDraft": True}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--work")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    file = Path(args.recipe).absolute()
    index = json.loads((file.parent / "recipe-index.json").read_text(encoding="utf-8"))
    expected = next(record for record in index["packages"] if record["recipe"] == file.name)
    if file.exists():
        if file.stat().st_size > 5 * 1024 ** 2: raise ValueError("Oversized recipe")
        encoded = file.read_bytes()
    else:
        pieces = expected.get("parts", [])
        if not 1 <= len(pieces) <= 32: raise ValueError("Missing recipe pieces")
        chunks = []
        for order, part in enumerate(pieces, 1):
            if part["name"] != f"{file.name}.{order:03d}": raise ValueError("Unsafe recipe piece")
            piece = file.parent / part["name"]
            if not 0 < piece.stat().st_size <= 256 * 1024: raise ValueError("Oversized recipe piece")
            content = piece.read_bytes()
            if len(content) != part["bytes"] or digest(content) != part["sha256"]: raise ValueError("Recipe piece changed")
            chunks.append(content)
        encoded = b"".join(chunks)
    if len(encoded) != expected["recipeBytes"] or digest(encoded) != expected["sha256"]: raise ValueError("Recipe changed since local review")
    recipe = json.loads(gzip.decompress(encoded))
    validate_recipe(recipe)
    if args.validate_only:
        print(json.dumps({"recipeValid": recipe["id"], "files": len(recipe["files"]), "downloadsStarted": 0})); return
    if not args.work or not Path(args.work).is_absolute(): raise ValueError("An explicit new build directory is required")
    build(recipe, Path(args.work))


if __name__ == "__main__":
    main()
