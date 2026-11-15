"""Unit tests for build-manifest component detection (DSR-055).

- Manifest discovery covers the eight supported build manifests and ignores
  everything else (shared with JVM build-evidence detection per DA-03).
- Every manifest file's directory is a component root; each file belongs to
  its NEAREST (deepest) enclosing root, nested roots included.
- Component labels are deterministic: the root's snapshot-relative directory,
  or the manifest file name when the root is the snapshot top level.
- Files outside every root map to "default"; a top-level manifest root covers
  the whole tree.
"""

import unittest

from auditkit.inventory.components import (
    BUILD_MANIFEST_FILE_NAMES,
    DEFAULT_COMPONENT,
    component_roots,
    detect_components,
    find_build_manifest_paths,
)


class TestFindBuildManifestPaths(unittest.TestCase):

    def test_all_supported_manifests_are_discovered(self):
        paths = [
            "pom.xml",
            "services/api/package.json",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "go.mod",
            "Cargo.toml",
            "src/Main.kt",
            "README.md",
        ]
        self.assertEqual(
            find_build_manifest_paths(paths),
            [
                "Cargo.toml",
                "build.gradle",
                "build.gradle.kts",
                "go.mod",
                "pom.xml",
                "services/api/package.json",
                "settings.gradle",
                "settings.gradle.kts",
            ],
        )

    def test_non_manifest_files_are_ignored(self):
        self.assertEqual(find_build_manifest_paths(["app.py", "docs/pom.md"]), [])
        # "./"-prefixed entries normalize to snapshot-relative paths.
        self.assertEqual(find_build_manifest_paths(["./go.mod"]), ["go.mod"])

    def test_every_supported_name_is_a_manifest(self):
        for name in BUILD_MANIFEST_FILE_NAMES:
            self.assertEqual(find_build_manifest_paths([name]), [name])


class TestComponentRoots(unittest.TestCase):

    def test_root_directory_and_label(self):
        roots = component_roots(["svc-a/pom.xml", "web/package.json", "go.mod"])
        # Deepest roots first; the top-level root ("") is labelled with the
        # manifest file's own name.
        self.assertEqual(roots, [
            {"root": "svc-a", "manifest": "svc-a/pom.xml", "label": "svc-a"},
            {"root": "web", "manifest": "web/package.json", "label": "web"},
            {"root": "", "manifest": "go.mod", "label": "go.mod"},
        ])

    def test_two_manifests_in_one_directory_are_both_roots(self):
        roots = component_roots(["svc/pom.xml", "svc/package.json"])
        # Same root directory -> same component label (the directory); both
        # manifest records stay distinguishable via "manifest".
        self.assertEqual(
            [(r["root"], r["label"], r["manifest"]) for r in roots],
            [("svc", "svc", "svc/package.json"), ("svc", "svc", "svc/pom.xml")],
        )


class TestDetectComponents(unittest.TestCase):

    def test_files_belong_to_nearest_enclosing_root(self):
        files = [
            {"path": "svc-a/pom.xml"},
            {"path": "svc-a/src/Repo.kt"},
            {"path": "svc-a/src/deep/Util.kt"},
            {"path": "web/package.json"},
            {"path": "web/src/api.ts"},
            {"path": "loose.py"},
        ]
        assignment = detect_components(files)
        self.assertEqual(assignment["svc-a/pom.xml"], "svc-a")
        self.assertEqual(assignment["svc-a/src/Repo.kt"], "svc-a")
        self.assertEqual(assignment["svc-a/src/deep/Util.kt"], "svc-a")
        self.assertEqual(assignment["web/package.json"], "web")
        self.assertEqual(assignment["web/src/api.ts"], "web")
        self.assertEqual(assignment["loose.py"], DEFAULT_COMPONENT)

    def test_nested_roots_win_over_outer_roots(self):
        files = [
            {"path": "go.mod"},
            {"path": "cmd/tool/main.go"},
            {"path": "cmd/tool/vendor/extra/go.mod"},
            {"path": "cmd/tool/vendor/extra/deep/x.go"},
            {"path": "other/lib.go"},
        ]
        assignment = detect_components(files)
        # The top-level root covers the whole tree...
        self.assertEqual(assignment["cmd/tool/main.go"], "go.mod")
        self.assertEqual(assignment["other/lib.go"], "go.mod")
        # ...but the nested go.mod wins for its own subtree (nearest root).
        self.assertEqual(assignment["cmd/tool/vendor/extra/go.mod"], "cmd/tool/vendor/extra")
        self.assertEqual(assignment["cmd/tool/vendor/extra/deep/x.go"], "cmd/tool/vendor/extra")

    def test_top_level_label_uses_manifest_name(self):
        assignment = detect_components([{"path": "package.json"}, {"path": "app.ts"}])
        self.assertEqual(assignment["package.json"], "package.json")
        self.assertEqual(assignment["app.ts"], "package.json")

    def test_no_manifests_means_everything_is_default(self):
        files = [{"path": "a.py"}, {"path": "dir/b.py"}, {"path": "go.sum"}]
        assignment = detect_components(files)
        self.assertEqual(set(assignment.values()), {DEFAULT_COMPONENT})

    def test_accepts_plain_path_strings(self):
        assignment = detect_components(["svc-a/pom.xml", "svc-a/src/Repo.kt"])
        self.assertEqual(assignment, {"svc-a/pom.xml": "svc-a", "svc-a/src/Repo.kt": "svc-a"})

    def test_deterministic_for_repeated_calls(self):
        files = [{"path": "a/pom.xml"}, {"path": "a/x.java"}, {"path": "b.py"}]
        self.assertEqual(detect_components(files), detect_components(list(files)))

    def test_absolute_paths_are_normalized_against_snapshot_root(self):
        files = [{"path": "/tmp/snap/svc-a/pom.xml"}, {"path": "/tmp/snap/svc-a/A.java"}]
        assignment = detect_components(files, "/tmp/snap")
        self.assertEqual(assignment["/tmp/snap/svc-a/pom.xml"], "svc-a")

    def test_path_escaping_snapshot_root_maps_to_default(self):
        assignment = detect_components([{"path": "../outside/a.py"}])
        self.assertEqual(assignment["../outside/a.py"], DEFAULT_COMPONENT)


if __name__ == "__main__":
    unittest.main()
