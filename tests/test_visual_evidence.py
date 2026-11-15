"""Disclosure-boundary regressions for the reviewed portfolio captures."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("visual_quality", ROOT / "tools/check_repository.py")
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(extra=b""):
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + extra + chunk(b"IDAT", zlib.compress(b"\0\0\0\0")) + chunk(b"IEND", b""))


def record(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "width": 1, "height": 1}


class VisualEvidenceTests(unittest.TestCase):
    def test_other_images_and_private_sources_remain_protected(self):
        for name in ("capture.png", "docs/evidence/new.png", "Planning/capture.png", "private-evidence/image.png", "docs/evidence/key.pem"):
            self.assertTrue(Q.protected(Path(name)), name)

    def test_allowlist_is_exact_and_does_not_allow_path_variants(self):
        self.assertEqual(len(Q.REVIEWED_IMAGE_PATHS), 8)
        for name in Q.REVIEWED_IMAGE_PATHS:
            self.assertFalse(Q.protected(Path(name)))
            self.assertTrue(Q.protected(Path("unapproved") / name))
            self.assertTrue(Q.protected(Path("Planning/..") / name))

    def test_valid_bounded_png_and_actual_reviewed_images(self):
        data = png()
        self.assertEqual(Q.inspect_reviewed_png(data, record(data)), [])
        records = Q.load_reviewed_images((ROOT / "docs/visual-evidence.json").read_text())
        for name, expected in records.items():
            self.assertEqual(Q.inspect_reviewed_png((ROOT / name).read_bytes(), expected), [], name)

    def test_replaced_pixels_require_new_reviewed_digest(self):
        data = png()
        altered = bytearray(data)
        altered[45] ^= 1
        self.assertEqual(Q.inspect_reviewed_png(bytes(altered), record(data)), ["image bytes differ from reviewed digest"])

    def test_metadata_and_animation_chunks_are_rejected(self):
        for kind in (b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"acTL"):
            data = png(chunk(kind, b"synthetic metadata"))
            self.assertTrue(Q.inspect_reviewed_png(data, record(data)))

    def test_corrupt_crc_is_rejected_even_with_matching_digest(self):
        data = bytearray(png())
        data[-1] ^= 1
        data = bytes(data)
        self.assertEqual(Q.inspect_reviewed_png(data, record(data)), ["PNG chunk checksum mismatch"])

    def test_dimensions_must_match_reviewed_record(self):
        data = png()
        for value in (2, 0, 1601):
            expected = record(data)
            expected["width"] = value
            self.assertTrue(Q.inspect_reviewed_png(data, expected))

    def test_size_truncation_and_appended_content_fail_closed(self):
        for data in (png()[:-3], png() + b"private attachment", b"x" * (Q.MAX_IMAGE_BYTES + 1)):
            self.assertTrue(Q.inspect_reviewed_png(data, record(data)))

    def test_image_links_and_html_links_are_checked_without_binary_text_reads(self):
        name = sorted(Q.REVIEWED_IMAGE_PATHS)[0]
        self.assertEqual(Q.check_links(ROOT / "README.md", f'<a href="{name}"><img src="{name}"></a>', ROOT), [])
        self.assertEqual(Q.check_links(ROOT / "README.md", f"[image]({name}#hidden)", ROOT), ["documentation anchor on non-Markdown artifact"])
        self.assertEqual(Q.check_links(ROOT / "README.md", '<img src="Planning/unread.png">', ROOT), ["unsafe documentation link"])

    def test_manifest_cannot_add_or_substitute_paths_or_exceed_budget(self):
        source = json.loads((ROOT / "docs/visual-evidence.json").read_text())
        for mutation in ("unknown", "duplicate", "extra", "oversize", "wrong-total"):
            data = deepcopy(source)
            if mutation == "unknown": data["images"][0]["path"] = "private-evidence/image.png"
            if mutation == "duplicate": data["images"][0] = data["images"][1]
            if mutation == "extra": data["images"].append(data["images"][0])
            if mutation == "oversize": data["images"][0]["bytes"] = Q.MAX_IMAGE_BYTES + 1
            if mutation == "wrong-total": data["total_bytes"] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                Q.load_reviewed_images(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
