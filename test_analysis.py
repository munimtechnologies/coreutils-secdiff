# SPDX-License-Identifier: Apache-2.0
# Unit tests for analysis.py (pure Python; run anywhere with `python -m unittest`).
import unittest

import analysis as A


class TestParsing(unittest.TestCase):
    def test_split_args_quotes_and_brackets(self):
        s = 'AT_FDCWD</tmp/a>, "x, y", {flags=O_CREAT|O_WRONLY, mode=0600}, 24'
        self.assertEqual(
            A.split_args(s),
            ["AT_FDCWD</tmp/a>", '"x, y"', "{flags=O_CREAT|O_WRONLY, mode=0600}", "24"],
        )

    def test_join_unfinished(self):
        lines = [
            '10 openat(AT_FDCWD</w>, "f", O_WRONLY|O_CREAT, 0644 <unfinished ...>',
            "11 umask(022)                       = 022",
            "10 <... openat resumed>)            = 3</w/f>",
        ]
        joined = A.join_lines(lines)
        self.assertEqual(len(joined), 2)
        pid, body = joined[1]
        self.assertEqual(pid, 10)
        m = A.CALL_RE.match(body)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "openat")
        self.assertEqual(A.split_args(m.group(2))[3], "0644")
        self.assertEqual(A.parse_ret(m.group(3)), ("3", "/w/f"))

    def test_parse_mode(self):
        self.assertEqual(A.parse_mode("0600"), 0o600)
        self.assertEqual(A.parse_mode("S_IFIFO|0644"), 0o644)
        self.assertEqual(A.parse_mode("04755"), 0o4755)
        self.assertIsNone(A.parse_mode('""'))
        self.assertIsNone(A.parse_mode("O_RDONLY"))

    def test_parse_ret(self):
        self.assertEqual(A.parse_ret("3</w/f>"), ("3", "/w/f"))
        self.assertEqual(A.parse_ret("-1 ENOENT (No such file or directory)"), ("-1", None))
        self.assertEqual(A.parse_ret("0"), ("0", None))

    def test_resolve(self):
        self.assertEqual(A.resolve("AT_FDCWD</w>", '"a/../b"', "/x"), "/w/b")
        self.assertEqual(A.resolve("AT_FDCWD", '"b"', "/x"), "/x/b")
        self.assertEqual(A.resolve("5</d>", '""', "/x"), "/d")
        self.assertEqual(A.resolve(None, '"/abs/p"', "/x"), "/abs/p")
        self.assertEqual(A.resolve("AT_FDCWD", '"/proc/self/fd/7"', "/x", {7: "/w/f"}), "/w/f")


class TestWindows(unittest.TestCase):
    def test_window_open_then_fchmod(self):
        lines = [
            '100 openat(AT_FDCWD</w>, "dst/secret", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3</w/dst/secret>',
            "100 fchmod(3</w/dst/secret>, 0600) = 0",
        ]
        r = A.analyze_trace(lines, "/w", 0o022, pre_paths={"/w", "/w/dst"},
                            final_modes={"/w/dst/secret": 0o600}, roots=("/w",))
        self.assertEqual(len(r["windows"]), 1)
        w = r["windows"][0]
        self.assertEqual(w["leaked_bits"], oct(0o044))
        self.assertEqual(w["fixed_by"], "fd")

    def test_no_window_when_created_restrictive(self):
        lines = [
            '100 openat(AT_FDCWD</w>, "dst/secret", O_WRONLY|O_CREAT|O_EXCL, 0600) = 3</w/dst/secret>',
            "100 fchmod(3</w/dst/secret>, 0600) = 0",
        ]
        r = A.analyze_trace(lines, "/w", 0o022, final_modes={"/w/dst/secret": 0o600})
        self.assertEqual(r["windows"], [])

    def test_existing_file_is_not_created(self):
        lines = ['1 openat(AT_FDCWD</w>, "f", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/f>']
        r = A.analyze_trace(lines, "/w", 0o022, pre_paths={"/w/f"}, final_modes={"/w/f": 0o600})
        self.assertEqual(r["created"], 0)

    def test_umask_call_tracked(self):
        lines = [
            "1 umask(000) = 022",
            '1 mkdirat(AT_FDCWD</w>, "d", 0777) = 0',
            '1 chmod("/w/d", 0700) = 0',
        ]
        r = A.analyze_trace(lines, "/w", 0o022, final_modes={"/w/d": 0o700})
        self.assertEqual(r["windows"][0]["created_mode"], oct(0o777))
        self.assertEqual(r["windows"][0]["fixed_by"], "path")
        self.assertEqual(len(r["path_chmods_on_created"]), 1)

    def test_rename_moves_creation(self):
        lines = [
            '1 openat(AT_FDCWD</w>, ".tmp1", O_WRONLY|O_CREAT|O_EXCL, 0644) = 3</w/.tmp1>',
            '1 renameat2(AT_FDCWD</w>, ".tmp1", AT_FDCWD</w>, "final", 0) = 0',
        ]
        r = A.analyze_trace(lines, "/w", 0o022, final_modes={"/w/final": 0o600})
        self.assertEqual(r["windows"][0]["path"], "/w/final")

    def test_failed_calls_ignored(self):
        lines = ['1 openat(AT_FDCWD</w>, "x", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)']
        r = A.analyze_trace(lines, "/w", 0o022, final_modes={"/w/x": 0o600})
        self.assertEqual(r["created"], 0)

    def test_suid_before_chown(self):
        lines = [
            '1 openat(AT_FDCWD</w>, "s", O_WRONLY|O_CREAT|O_EXCL, 0600) = 3</w/s>',
            "1 fchmod(3</w/s>, 04755) = 0",
            "1 fchown(3</w/s>, 1001, 1001) = 0",
        ]
        r = A.analyze_trace(lines, "/w", 0o022, final_modes={"/w/s": 0o755})
        self.assertEqual(len(r["suid_before_chown"]), 1)

    def test_roots_filter(self):
        lines = ['1 openat(AT_FDCWD</w>, "/etc/x", O_WRONLY|O_CREAT, 0666) = 3</etc/x>']
        r = A.analyze_trace(lines, "/w", 0o022, roots=("/w",), final_modes={"/etc/x": 0o600})
        self.assertEqual(r["created"], 0)

    def test_garbage_lines_do_not_crash(self):
        lines = ["", "1 +++ exited with 0 +++", "nonsense", "1 chmod() = 0", "1 openat() = 3"]
        r = A.analyze_trace(lines, "/w", 0o022)
        self.assertEqual(r["windows"], [])


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.pre = {
            "w/src/secret": {"type": "f", "mode": 0o600, "uid": "user", "gid": "user", "size": 7, "sha": "a"},
            "outside/target": {"type": "f", "mode": 0o644, "uid": "user", "gid": "user", "size": 7, "sha": "t"},
        }

    def test_identical(self):
        self.assertEqual(A.snapshot_diff(self.pre, dict(self.pre)), [])

    def test_more_permissive_and_outside(self):
        uu = dict(self.pre)
        uu["w/dst/secret"] = {"type": "f", "mode": 0o644, "uid": "user", "gid": "user", "size": 7, "sha": "a"}
        uu["outside/target"] = dict(self.pre["outside/target"], sha="z")
        gnu = dict(self.pre)
        gnu["w/dst/secret"] = {"type": "f", "mode": 0o600, "uid": "user", "gid": "user", "size": 7, "sha": "a"}
        flags = A.classify(A.snapshot_diff(gnu, uu), self.pre)
        self.assertIn("uu_more_permissive", flags)
        self.assertIn("outside_differs", flags)
        self.assertIn("content", flags)

    def test_removed_and_created(self):
        gnu = dict(self.pre)
        uu = {"w/src/secret": self.pre["w/src/secret"], "outside/new": {"type": "f", "mode": 0o644}}
        flags = A.classify(A.snapshot_diff(gnu, uu), self.pre)
        self.assertIn("uu_removed_or_missing", flags)
        self.assertIn("uu_created_extra", flags)

    def test_special_bits(self):
        gnu = {"w/x": {"type": "f", "mode": 0o755, "uid": "user", "gid": "user"}}
        uu = {"w/x": {"type": "f", "mode": 0o4755, "uid": "user", "gid": "user"}}
        self.assertIn("special_bits", A.classify(A.snapshot_diff(gnu, uu), {}))

    def test_exit_and_trace_flags(self):
        self.assertEqual(A.exit_flags(0, 1), ["exit_status"])
        self.assertEqual(A.exit_flags(1, 1), [])
        self.assertEqual(A.exit_flags(0, "timeout"), ["uu_timeout"])
        g = {"windows": [], "suid_before_chown": []}
        u = {"windows": [{"path": "<B>/w/dst/x"}], "suid_before_chown": []}
        self.assertEqual(A.trace_flags(g, u), ["uu_perm_window"])
        self.assertEqual(A.trace_flags(u, u), [])

    def test_normalize(self):
        s = A.normalize_text("/tmp/sd/uu/x/w/dst/tmp.AbC123xy and /dev/shm/sd/uu/x",
                             [("/tmp/sd/uu/x", "<B>"), ("/dev/shm/sd/uu/x", "<X>")])
        self.assertEqual(s, "<B>/w/dst/tmp.RAND and <X>")


if __name__ == "__main__":
    unittest.main()
