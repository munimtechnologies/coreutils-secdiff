# SPDX-License-Identifier: Apache-2.0
# Structural checks on the frozen scenario list, including the safety rule that no
# scenario argument can name "/" or any absolute path outside the fixture.
import unittest

import scenarios as SC


class TestScenarios(unittest.TestCase):
    def test_ids_unique_and_fields(self):
        ids = [s["id"] for s in SC.SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))
        for s in SC.SCENARIOS:
            self.assertIn(s["user"], ("root", "user"))
            self.assertTrue(s["id"].endswith("@" + s["user"]), s["id"])
            self.assertIsInstance(s["args"], list)
            self.assertTrue(all(isinstance(a, str) for a in s["args"]))
            self.assertIn(s["umask"], (0o000, 0o022, 0o077))
            self.assertTrue(s["cwd"] == "w" or s["cwd"].startswith("w/"))

    def test_no_absolute_or_root_paths(self):
        for s in SC.SCENARIOS:
            for a in s["args"]:
                value = a.split("=", 1)[1] if a.startswith(("if=", "of=", "--reference=")) else a
                self.assertFalse(value.startswith("/"), (s["id"], a))
                self.assertNotEqual(a, "/")
                self.assertNotIn("--no-preserve-root", a)

    def test_controls_exist(self):
        ids = {s["id"] for s in SC.SCENARIOS}
        for c in SC.CONTROL_IDS:
            self.assertIn(c, ids)

    def test_fixture_sane(self):
        paths = [f[0] for f in SC.FIXTURE]
        self.assertEqual(len(paths), len(set(paths)))
        for path, kind, _mode, _o, _g, data in SC.FIXTURE:
            self.assertIn(kind, "dflhp")
            self.assertFalse(path.startswith("/"))
            parent = path.rsplit("/", 1)[0] if "/" in path else None
            if parent:
                self.assertIn(parent, paths, path)
            if kind == "l":
                self.assertTrue(data.startswith("../") or data.startswith("{B}/"), path)

    def test_size(self):
        self.assertGreaterEqual(len(SC.SCENARIOS), 250)
        self.assertGreaterEqual(len(SC.TOOLS), 15)


if __name__ == "__main__":
    unittest.main()
