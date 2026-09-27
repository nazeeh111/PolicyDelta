"""Offline tests for the explicit, pinned OpenBao download helper."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import fetch_runtime


def archive(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
                tar.addfile(info)
    return buffer.getvalue()


class FetchRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / ".runtime"
        self.data = archive([
            ("./bao", b"binary", "file"),
            ("./LICENSE", b"external notice", "file"),
            ("./README.md", b"ignored", "file"),
        ])
        self.artifact = fetch_runtime.Artifact(
            "https://github.com/openbao/openbao/releases/download/v2.7.0/example.tar.gz",
            hashlib.sha256(self.data).hexdigest(),
        )

    def fetch(self, data=None, artifact=None):
        return fetch_runtime.fetch_runtime(
            self.destination,
            artifact or self.artifact,
            opener=lambda request, timeout: io.BytesIO(self.data if data is None else data),
        )

    def test_verified_archive_extracts_only_regular_engine_and_notice(self):
        self.fetch()
        self.assertEqual((self.destination / "bao").read_bytes(), b"binary")
        self.assertEqual((self.destination / "LICENSE").read_bytes(), b"external notice")
        self.assertEqual({p.name for p in self.destination.iterdir()}, {"bao", "LICENSE"})
        self.assertTrue((self.destination / "bao").stat().st_mode & 0o111)

    def test_existing_directory_is_preserved(self):
        self.destination.mkdir()
        (self.destination / "keep").write_text("user data")
        with self.assertRaises(FileExistsError):
            self.fetch()
        self.assertEqual((self.destination / "keep").read_text(), "user data")

    def test_bad_hash_cleans_its_new_directory(self):
        artifact = fetch_runtime.Artifact(self.artifact.url, "0" * 64)
        with self.assertRaisesRegex(fetch_runtime.FetchError, "SHA-256"):
            self.fetch(artifact=artifact)
        self.assertFalse(self.destination.exists())

    def test_oversized_download_cleans_its_new_directory(self):
        with mock.patch.object(fetch_runtime, "MAX_ARCHIVE_BYTES", 8):
            with self.assertRaisesRegex(fetch_runtime.FetchError, "size limit"):
                self.fetch()
        self.assertFalse(self.destination.exists())

    def test_missing_license_cleans_its_new_directory(self):
        data = archive([("bao", b"binary", "file")])
        artifact = fetch_runtime.Artifact(self.artifact.url, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(fetch_runtime.FetchError, "LICENSE"):
            self.fetch(data=data, artifact=artifact)
        self.assertFalse(self.destination.exists())

    def test_download_failure_cleans_its_new_directory(self):
        def fail(request, timeout):
            raise OSError("network unavailable")

        with self.assertRaisesRegex(OSError, "network unavailable"):
            fetch_runtime.fetch_runtime(self.destination, self.artifact, opener=fail)
        self.assertFalse(self.destination.exists())

    def test_link_cannot_replace_engine_or_license(self):
        data = archive([("bao", b"", "symlink"), ("LICENSE", b"notice", "file")])
        artifact = fetch_runtime.Artifact(self.artifact.url, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(fetch_runtime.FetchError, "regular file"):
            self.fetch(data=data, artifact=artifact)
        self.assertFalse(self.destination.exists())

    def test_duplicate_engine_is_rejected(self):
        data = archive([
            ("bao", b"first", "file"),
            ("./bao", b"second", "file"),
            ("LICENSE", b"notice", "file"),
        ])
        artifact = fetch_runtime.Artifact(self.artifact.url, hashlib.sha256(data).hexdigest())
        with self.assertRaisesRegex(fetch_runtime.FetchError, "duplicate"):
            self.fetch(data=data, artifact=artifact)
        self.assertFalse(self.destination.exists())

    def test_supported_platforms_are_explicit(self):
        self.assertEqual(fetch_runtime.select_artifact("Darwin", "arm64").sha256,
                         "cc9f9d4d969bbdeba7ffc8f3f3649d9372446847ffe2e1e618520c038c999641")
        self.assertEqual(fetch_runtime.select_artifact("Linux", "x86_64").sha256,
                         "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667")
        with self.assertRaisesRegex(fetch_runtime.FetchError, "Unsupported platform"):
            fetch_runtime.select_artifact("Windows", "amd64")


if __name__ == "__main__":
    unittest.main()
