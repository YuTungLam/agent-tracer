"""Keep incomplete or mismatched preparation results out of the GPU allocation."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import preflight


class DownloadReceiptTests(unittest.TestCase):
    def test_same_size_metadata_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "receipt.json"
            candidate = root / "config.json"
            original = b'{"ok":0}'
            candidate.write_bytes(original)
            model = {"model_id": "scout", "declared_revision": "a" * 40, "path": directory,
                     "files": [{"name": "config.json", "bytes": len(original)}]}
            for algorithm, expected in (
                ("sha256", hashlib.sha256(original).hexdigest()),
                ("git-blob-sha1", hashlib.sha1(f"blob {len(original)}\0".encode() + original).hexdigest()),
            ):
                data = {"model_id": "scout", "revision": "a" * 40, "snapshot": directory,
                        "status": "all_selected_files_verified", "files": [
                            {"path": "config.json", "bytes": len(original), "verified": True,
                             "algorithm": algorithm, "expected": expected}]}
                candidate.write_bytes(original)
                path.write_text(json.dumps(data))
                preflight.verify_download_receipt(path, model)
                candidate.write_bytes(b'{"ok":1}')
                with self.assertRaisesRegex(ValueError, "metadata differs"):
                    preflight.verify_download_receipt(path, model)

    def test_verified_snapshot_binding_and_negative_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            model = {"model_id": "scout", "declared_revision": "a" * 40, "path": directory,
                     "files": [{"name": "part.safetensors", "bytes": 10}]}
            data = {"model_id": "scout", "revision": "a" * 40, "snapshot": directory,
                    "status": "all_selected_files_verified", "files": [
                        {"path": "part.safetensors", "bytes": 10, "verified": True,
                         "algorithm": "sha256", "expected": "b" * 64}]}
            path.write_text(json.dumps(data))
            checked = preflight.verify_download_receipt(path, model)
            self.assertEqual(checked["status"], "all_selected_files_verified")
            self.assertFalse(checked["weight_hashes_rechecked_in_gpu_job"])
            mutations = [
                ("status", "downloading"), ("revision", "c" * 40),
                ("snapshot", directory + "-different"), ("files", []),
                ("files", data["files"] * 2),
            ]
            for key, value in mutations:
                with self.subTest(key=key, value=value):
                    changed = copy.deepcopy(data)
                    changed[key] = value
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        preflight.verify_download_receipt(path, model)
            for key, value in (("verified", False), ("bytes", 11), ("expected", "bad"),
                               ("algorithm", "git-blob-sha1")):
                with self.subTest(file_field=key):
                    changed = copy.deepcopy(data)
                    changed["files"][0][key] = value
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        preflight.verify_download_receipt(path, model)


if __name__ == "__main__":
    unittest.main()
