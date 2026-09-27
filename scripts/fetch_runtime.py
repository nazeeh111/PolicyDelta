"""Explicitly fetch a pinned OpenBao 2.7.0 binary for local PolicyDelta runs.

Run ``python scripts/fetch_runtime.py`` from any directory. This helper creates
PolicyDelta/.runtime once and refuses to alter an existing directory. OpenBao
and its LICENSE remain external artifacts under their original terms.
"""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import platform
import shutil
import tarfile
import time
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / ".runtime"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ENGINE_BYTES = 256 * 1024 * 1024
MAX_NOTICE_BYTES = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30
MAX_DOWNLOAD_SECONDS = 180
CHUNK_BYTES = 1024 * 1024


class FetchError(RuntimeError):
    """A download or verified archive cannot provide the selected runtime."""


@dataclass(frozen=True)
class Artifact:
    url: str
    sha256: str


ARTIFACTS = {
    ("darwin", "arm64"): Artifact(
        "https://github.com/openbao/openbao/releases/download/v2.7.0/openbao_2.7.0_darwin_arm64.tar.gz",
        "cc9f9d4d969bbdeba7ffc8f3f3649d9372446847ffe2e1e618520c038c999641",
    ),
    ("linux", "amd64"): Artifact(
        "https://github.com/openbao/openbao/releases/download/v2.7.0/openbao_2.7.0_linux_amd64.tar.gz",
        "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667",
    ),
}


def select_artifact(system: str, machine: str) -> Artifact:
    system = system.lower()
    machine = machine.lower()
    if system == "darwin" and machine == "aarch64":
        machine = "arm64"
    if system == "linux" and machine == "x86_64":
        machine = "amd64"
    try:
        return ARTIFACTS[(system, machine)]
    except KeyError as error:
        raise FetchError(f"Unsupported platform: {system}/{machine}") from error


def _download(destination: Path, artifact: Artifact, opener) -> None:
    digest = hashlib.sha256()
    size = 0
    started = time.monotonic()
    request = Request(artifact.url, headers={"User-Agent": "PolicyDelta-runtime-fetch/0.1"})
    with opener(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise FetchError(f"OpenBao download returned HTTP {status}")
        with destination.open("xb") as output:
            while True:
                chunk = response.read(CHUNK_BYTES)
                if time.monotonic() - started > MAX_DOWNLOAD_SECONDS:
                    raise FetchError("OpenBao download exceeded time limit")
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise FetchError("OpenBao download exceeds size limit")
                output.write(chunk)
                digest.update(chunk)
    if digest.hexdigest() != artifact.sha256:
        raise FetchError("OpenBao archive SHA-256 mismatch")


def _selected_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    selected = {}
    for index, member in enumerate(archive):
        if index >= 128:
            raise FetchError("OpenBao archive has too many members")
        name = member.name.removeprefix("./")
        if name not in {"bao", "LICENSE"}:
            continue
        if name in selected:
            raise FetchError(f"OpenBao archive has duplicate {name}")
        limit = MAX_ENGINE_BYTES if name == "bao" else MAX_NOTICE_BYTES
        if not member.isfile() or member.size <= 0 or member.size > limit:
            raise FetchError(f"OpenBao archive {name} must be a bounded regular file")
        selected[name] = member
    if set(selected) != {"bao", "LICENSE"}:
        raise FetchError("OpenBao archive must contain regular bao and LICENSE files")
    return selected


def fetch_runtime(destination: Path = DESTINATION, artifact: Artifact | None = None,
                  opener=urlopen) -> Path:
    """Create a fresh runtime directory; remove it if this attempt fails."""
    destination = Path(destination)
    if artifact is None:
        artifact = select_artifact(platform.system(), platform.machine())
    destination.mkdir(mode=0o700)  # FileExistsError protects all existing contents.
    download = destination / "archive.tar.gz"
    try:
        _download(download, artifact, opener)
        try:
            with tarfile.open(download, mode="r:gz") as archive:
                members = _selected_members(archive)
                for name in ("bao", "LICENSE"):
                    source = archive.extractfile(members[name])
                    if source is None:
                        raise FetchError(f"OpenBao archive cannot read {name}")
                    with source, (destination / name).open("xb") as output:
                        shutil.copyfileobj(source, output, CHUNK_BYTES)
            (destination / "bao").chmod(0o755)
            (destination / "LICENSE").chmod(0o644)
        except (tarfile.TarError, EOFError) as error:
            raise FetchError("OpenBao archive is invalid") from error
        download.unlink()
        return destination / "bao"
    except BaseException:
        # This directory was created above, so no previous runtime is removed.
        shutil.rmtree(destination)
        raise


def main(argv=None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Fetch verified OpenBao 2.7.0 into a fresh .runtime directory.")
    parser.parse_args(argv)
    try:
        engine = fetch_runtime()
    except (FetchError, FileExistsError, OSError) as error:
        print(f"PolicyDelta runtime: {error}", file=sys.stderr)
        return 1
    print(f"Verified OpenBao 2.7.0: {engine}")
    print(f"OpenBao license: {engine.parent / 'LICENSE'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
