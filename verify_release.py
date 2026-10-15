#!/usr/bin/env python3
"""Verify a signed product and upload a resumable GitHub draft; never read login tokens."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

ASSETS = ("product.json", "product.sig", "product.tar.gz", "seisaku-linux-amd64.run", "publisher.pub")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def hash_region(stream, size):
    result = hashlib.sha256()
    while size:
        part = stream.read(min(size, 1024 * 1024))
        if not part:
            raise ValueError("truncated installer")
        result.update(part)
        size -= len(part)
    return result.hexdigest()


def verify(directory, public_key):
    key = bytes.fromhex(public_key.read_text().strip())
    if len(key) != 32 or directory.joinpath("publisher.pub").read_text().strip() != key.hex():
        raise ValueError("release publisher differs from the independently trusted key")
    for name in ASSETS:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing regular release asset: " + name)
    if (directory / "product.json").stat().st_size > 32 * 1024 * 1024:
        raise ValueError("oversize manifest")
    with tempfile.TemporaryDirectory() as temporary:
        der = Path(temporary) / "public.der"
        der.write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                        "-inkey", str(der), "-in", str(directory / "product.json"),
                        "-sigfile", str(directory / "product.sig")], check=True, capture_output=True)
    raw = (directory / "product.json").read_bytes()
    signature = (directory / "product.sig").read_bytes()
    manifest = json.loads(raw)
    if (manifest["format"] != "seisaku.product/v1" or manifest["channel"] not in ("stable", "preview")
            or manifest["platform"] != "linux-amd64" or type(manifest["sequence"]) is not int
            or not 0 < manifest["sequence"] < 2**64
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", manifest["version"])
            or datetime.fromisoformat(manifest["expires"].replace("Z", "+00:00")) <= datetime.now(timezone.utc)):
        raise ValueError("invalid or expired release identity")
    for name in manifest["files"]:
        if (name.startswith(("backend/docs/", "backend/acceptance/", "backend/deployment/test_", "backend/deployment/docker/"))
                or "/.git/" in name or name.endswith((".seed", ".js.map", ".ts.map"))):
            raise ValueError("development-only or secret file in public product: " + name)
    archive = directory / "product.tar.gz"
    if archive.stat().st_size != manifest["archiveSize"] or digest(archive) != manifest["archiveSha256"]:
        raise ValueError("archive differs from signed inventory")
    # Authenticate the complete downloadable installer, including its bootstrap,
    # without executing any code supplied by the candidate.
    installer = directory / "seisaku-linux-amd64.run"
    magic = b"SEISAKU-BUNDLE-1\n"
    with installer.open("rb") as stream:
        stream.seek(-len(magic)-24, 2)
        footer = stream.read()
        if footer[:len(magic)] != magic:
            raise ValueError("installer footer missing")
        bootstrap, archive_size, metadata_size = struct.unpack("<QQQ", footer[len(magic):])
        if (archive_size != manifest["archiveSize"] or metadata_size != len(raw)
                or installer.stat().st_size != bootstrap + archive_size + metadata_size + 64 + 32 + len(footer)):
            raise ValueError("installer boundaries differ from signed release")
        stream.seek(0)
        entry = manifest["files"]["backend/bin/seisaku-install"]
        if bootstrap != entry["size"] or hash_region(stream, bootstrap) != entry["sha256"]:
            raise ValueError("installer bootstrap differs from signed inventory")
        if hash_region(stream, archive_size) != manifest["archiveSha256"]:
            raise ValueError("embedded archive differs from signed inventory")
        if stream.read(metadata_size) != raw or stream.read(64) != signature or stream.read(32) != key:
            raise ValueError("embedded trust or manifest differs from release")
    return manifest


def gh(*arguments):
    return subprocess.check_output(["gh", *arguments], text=True)


def release_tag(manifest):
    return f'{manifest["channel"]}-{manifest["sequence"]:020d}-linux-amd64'


def upload(directory, repository, manifest):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", repository):
        raise ValueError("invalid release repository")
    tag = release_tag(manifest)
    releases = json.loads(gh("api", f"repos/{repository}/releases?per_page=100", "--paginate", "--slurp"))
    existing = None
    for page in releases:
        for release in page:
            if release["tag_name"] == tag:
                existing = release
            match = re.fullmatch(manifest["channel"] + r"-([0-9]{20})-linux-amd64", release["tag_name"])
            if not release["draft"] and match and int(match[1]) >= manifest["sequence"]:
                raise ValueError("release sequence has already been published or superseded")
    if existing is None:
        notes = (f'Seisaku {manifest["version"]} — Linux x86-64, {manifest["channel"]} channel.\n\n'
                 'Download `seisaku-linux-amd64.run`, make it executable, and open it to start graphical setup. '
                 'Existing installations can use Updates in the application.\n\n'
                 'This initial preview is qualified on Fedora 44. Other Linux distributions are not yet qualified.\n'
                 'GitHub CLI owns GitHub login; Nexus owns provider login. No credentials are included.\n')
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt") as file:
            file.write(notes); file.flush()
            args = ["release", "create", tag, "--repo", repository, "--draft", "--title", "Seisaku " + manifest["version"],
                    "--notes-file", file.name, "--target", "main"]
            if manifest["channel"] == "preview":
                args.append("--prerelease")
            gh(*args)
        for attempt in range(6):
            pages = json.loads(gh("api", f"repos/{repository}/releases?per_page=100", "--paginate", "--slurp"))
            existing = next((release for page in pages for release in page if release["tag_name"] == tag), None)
            if existing is not None:
                break
            time.sleep(min(2 ** attempt, 8))
        if existing is None:
            raise ValueError("GitHub has not exposed the new draft yet; retry to resume the upload")
    if not existing["draft"]:
        raise ValueError("published releases cannot be replaced")
    assets = {asset["name"]: asset for asset in existing["assets"]}
    if set(assets) - set(ASSETS):
        raise ValueError("draft contains unexpected assets")
    for name in ASSETS:
        if name in assets:
            expected = "sha256:" + digest(directory / name)
            if assets[name].get("digest") != expected:
                raise ValueError("existing draft asset differs or has no verified GitHub digest: " + name)
        else:
            gh("release", "upload", tag, str(directory / name), "--repo", repository)
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--repository", default="leiringer-ai/seisaku-releases")
    parser.add_argument("--upload", action="store_true")
    args = parser.parse_args()
    manifest = verify(args.directory, args.public_key)
    tag = upload(args.directory, args.repository, manifest) if args.upload else release_tag(manifest)
    print(json.dumps({"tag": tag, "version": manifest["version"], "channel": manifest["channel"], "state": "draft" if args.upload else "verified"}))


if __name__ == "__main__":
    main()
