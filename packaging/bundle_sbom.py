#!/usr/bin/env python3
"""Validate and bundle the four release SBOMs using only the standard library."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import parse_qs, urlsplit
import zipfile


TARGETS = ("darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64")
ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def validate_document(data: bytes, release: str, target: str) -> None:
    document = json.loads(data)
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{target}: not a CycloneDX document")
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict) or component.get("version") != release:
        raise ValueError(f"{target}: SBOM version does not match {release}")
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        raise ValueError(f"{target}: missing component package URL")
    qualifiers = parse_qs(urlsplit(purl).query, keep_blank_values=True)
    target_os, target_arch = target.split("_", 1)
    if qualifiers.get("goos") != [target_os] or qualifiers.get("goarch") != [target_arch]:
        raise ValueError(f"{target}: SBOM platform does not match its filename")


def verify_bundle(path: Path, documents: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != sorted(documents) or archive.comment:
            raise ValueError("SBOM ZIP contains unexpected entries or metadata")
        if archive.testzip() is not None:
            raise ValueError("SBOM ZIP failed its CRC check")
        for info in archive.infolist():
            if (
                info.date_time != ZIP_DATE
                or info.create_system != 3
                or info.external_attr != (stat.S_IFREG | 0o644) << 16
                or info.compress_type != zipfile.ZIP_STORED
                or info.extra
                or info.comment
                or archive.read(info) != documents[info.filename]
            ):
                raise ValueError(f"SBOM ZIP verification failed: {info.filename}")


def bundle_sbom(directory: Path, release: str) -> Path:
    if re.fullmatch(r"v[0-9][A-Za-z0-9._+-]*", release) is None:
        raise ValueError("release must be a safe version tag starting with v and a digit")
    directory = Path(directory)
    output = directory / f"moto_{release}_sbom.zip"
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"refusing to overwrite {output}")
    names = {f"moto_{release}_{target}.sbom.cdx.json": target for target in TARGETS}
    allowed = set(names) | {f"moto_{release}_{target}.tar.gz" for target in TARGETS}
    unexpected = sorted(path.name for path in directory.iterdir() if path.name not in allowed)
    if unexpected:
        raise ValueError(f"unexpected release files: {', '.join(unexpected)}")
    documents = {}
    for name, target in sorted(names.items()):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or non-regular SBOM: {name}")
        data = path.read_bytes()
        validate_document(data, release, target)
        documents[name] = data

    # Stored entries avoid compression-library differences; fixed metadata makes
    # the bundle byte-for-byte reproducible on macOS and Linux.
    descriptor, temporary_name = tempfile.mkstemp(prefix=".sbom-", suffix=".zip", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, data in sorted(documents.items()):
                    info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, data)
        verify_bundle(temporary, documents)
        for name, data in documents.items():
            path = directory / name
            if path.is_symlink() or path.read_bytes() != data:
                raise ValueError(f"SBOM changed while bundling: {name}")
        os.chmod(temporary, 0o644)
        # Atomic no-clobber publication, unlike rename/replace on Unix.
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    for name in documents:
        (directory / name).unlink()
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="clean release asset directory")
    parser.add_argument("release", help="release tag, e.g. v1.0.1")
    args = parser.parse_args()
    try:
        print(bundle_sbom(args.directory, args.release))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.exit(1, f"SBOM bundle failed: {error}\n")


if __name__ == "__main__":
    main()
