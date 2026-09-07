"""Atomic tests for C2 wordlist capabilities (release directive):

  - registry merge: generated full-SecLists index + custom lists index merge
    into the selectable universe; curated keys always win collisions
  - allow_registry_wide: DNSR-1/FFUF-0/FFUF-2 offer every registered list;
    a task WITHOUT the flag stays restricted to its registered keys
  - seclists sync: deterministic frozen-loader-dialect index generation
  - custom list CRUD: validation laws (name, charset, size, secrets),
    idempotent re-add, protected platform-learned list
  - platform learning: run-end label ingest, append-only + deduplicated,
    scope law, nested x.y label form
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ci"))

from pipeline.custom_lists import (  # noqa: E402
    CustomListError,
    add_custom_list,
    ensure_learned_list,
    ingest_learned_labels,
    list_custom_lists,
    normalize_lines,
    remove_custom_list,
)
from pipeline.params import Params  # noqa: E402
from pipeline.seclists_sync import build_index_doc, render_index, slug_for  # noqa: E402
from pipeline.wordlists import WordlistError, WordlistRegistry  # noqa: E402
from pipeline.yaml_util import load_yaml_file  # noqa: E402

WORDLISTS_YAML = """schema_version: 1
lists:
  curated_one:
    path: Discovery/DNS/curated-one.txt
    entries: 3
    shape: hostname
    rationale: "curated fixture entry"
tasks:
  DNSR-1:
    default_key: curated_one
    allow_registry_wide: true
    sources:
      - curated_one
  FFUF-0:
    default_key: curated_one
    allow_registry_wide: true
    default_selection:
      - curated_one
    sources:
      - curated_one
  FFUF-2:
    default_key: curated_one
    allow_registry_wide: true
    sources:
      - curated_one
  RESTRICTED:
    default_key: curated_one
    sources:
      - curated_one
"""

TOOLS_YAML = """settings:
  wordlists_registry: wordlists.yaml
  seclists_root: /usr/share/seclists
  seclists_host_path: {seclists_host}
  wordlists_generated_index: wordlists/seclists-index.yaml
  wordlists_custom_index: wordlists/custom/index.yaml
"""


def make_root(tmp: Path, seclists_host: Path | None) -> Path:
    (tmp / "wordlists" / "custom").mkdir(parents=True)
    (tmp / "wordlists.yaml").write_text(WORDLISTS_YAML, encoding="utf-8")
    (tmp / "tools.yaml").write_text(
        TOOLS_YAML.format(seclists_host=str(seclists_host or tmp / "seclists-missing")),
        encoding="utf-8",
    )
    return tmp


def write_generated_index(root: Path, lists: dict[str, dict]) -> None:
    doc = {"schema_version": 1, "root": "seclists", "lists": lists}
    (root / "wordlists").mkdir(exist_ok=True)
    (root / "wordlists" / "seclists-index.yaml").write_text(render_index(doc), encoding="utf-8")


def write_custom_index(root: Path, lists: dict[str, dict]) -> None:
    lines = ["schema_version: 1", "root: wordlists/custom", "lists:"]
    for key, e in lists.items():
        lines += [f"  {key}:", f"    path: {e['path']}", f"    entries: {e['entries']}",
                  f"    shape: {e['shape']}", f"    origin: {e.get('origin', 'operator')}"]
    (root / "wordlists" / "custom").mkdir(parents=True, exist_ok=True)
    (root / "wordlists" / "custom" / "index.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


class RegistryMerge(unittest.TestCase):
    def test_generated_and_custom_indexes_merge_in(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(Path(td), None)
            write_generated_index(root, {
                "sl_discovery__dns__big": {"path": "Discovery/DNS/big.txt", "entries": 1000, "shape": "hostname"},
                "sl_fuzzing__paths": {"path": "Fuzzing/paths.txt", "entries": 50, "shape": "generic"},
            })
            write_custom_index(root, {
                "platform_learned": {"path": "wordlists/custom/platform-learned.txt", "entries": 2,
                                     "shape": "hostname", "origin": "platform"},
            })
            reg = WordlistRegistry(Params(root))
            self.assertIn("sl_discovery__dns__big", reg.lists)
            self.assertIn("platform_learned", reg.lists)
            self.assertEqual(len(reg.generated_index), 2)
            self.assertEqual(len(reg.custom_index), 1)

    def test_curated_key_wins_collision(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(Path(td), None)
            write_generated_index(root, {
                "curated_one": {"path": "EVIL/override.txt", "entries": 1, "shape": "generic"},
            })
            reg = WordlistRegistry(Params(root))
            self.assertEqual(reg.relative_path("curated_one"), "Discovery/DNS/curated-one.txt")
            self.assertEqual(len(reg.generated_index), 0)

    def test_registry_wide_tasks_offer_everything(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(Path(td), None)
            write_generated_index(root, {
                "sl_discovery__dns__big": {"path": "Discovery/DNS/big.txt", "entries": 1000, "shape": "hostname"},
            })
            write_custom_index(root, {
                "platform_learned": {"path": "wordlists/custom/platform-learned.txt", "entries": 0,
                                     "shape": "hostname", "origin": "platform"},
            })
            reg = WordlistRegistry(Params(root))
            for task in ("DNSR-1", "FFUF-0", "FFUF-2"):
                allowed = reg.allowed_keys(task)
                self.assertIn("sl_discovery__dns__big", allowed, task)
                self.assertIn("platform_learned", allowed, task)
            restricted = reg.allowed_keys("RESTRICTED")
            self.assertNotIn("sl_discovery__dns__big", restricted)
            self.assertNotIn("platform_learned", restricted)

    def test_resolve_rejects_raw_paths_still(self):
        with tempfile.TemporaryDirectory() as td:
            root = make_root(Path(td), None)
            reg = WordlistRegistry(Params(root))
            with self.assertRaises(WordlistError):
                reg.allowed_keys("NO-SUCH-TASK")


class SeclistsSync(unittest.TestCase):
    def test_sync_deterministic_and_parses(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as sd:
            root = make_root(Path(td), Path(sd))
            sec = Path(sd) / "Discovery" / "DNS"
            sec.mkdir(parents=True)
            (sec / "a.txt").write_text("www\napi\nmail\n", encoding="utf-8")
            (sec / "b.txt").write_text("one\ntwo\n", encoding="utf-8")
            (Path(sd) / "Fuzzing").mkdir()
            (Path(sd) / "Fuzzing" / "words.txt").write_text("admin\n", encoding="utf-8")
            (Path(sd) / "empty.txt").write_text("", encoding="utf-8")
            from pipeline.seclists_sync import sync_seclists_index
            ledger = sync_seclists_index(Params(root))
            self.assertEqual(ledger["lists"], 3)  # empty.txt skipped
            first = (root / "wordlists" / "seclists-index.yaml").read_bytes()
            sync_seclists_index(Params(root))
            second = (root / "wordlists" / "seclists-index.yaml").read_bytes()
            self.assertEqual(first, second)  # deterministic
            doc = load_yaml_file(str(root / "wordlists" / "seclists-index.yaml"))
            self.assertEqual(int(doc["lists"]["sl_discovery__dns__a"]["entries"]), 3)
            self.assertEqual(doc["lists"]["sl_discovery__dns__a"]["shape"], "hostname")
            self.assertEqual(doc["lists"]["sl_fuzzing__words"]["shape"], "generic")

    def test_slug_stability(self):
        self.assertEqual(slug_for(Path("Discovery/DNS/x.txt")), "sl_discovery__dns__x")


class CustomLists(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self._tmp.name), None)
        self.params = Params(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_source(self, name: str, text: str) -> Path:
        p = self.root / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_add_valid_list(self):
        src = self._write_source("good.txt", "admin\nbackup\ndev\nadmin\n")
        ledger = add_custom_list(self.params, "my-list", src)
        self.assertEqual(ledger["entries"], 3)  # deduped
        doc = load_yaml_file(str(self.root / "wordlists" / "custom" / "index.yaml"))
        self.assertEqual(int(doc["lists"]["my-list"]["entries"]), 3)
        reg = WordlistRegistry(self.params)
        self.assertIn("my-list", reg.allowed_keys("DNSR-1"))

    def test_re_add_idempotent(self):
        src = self._write_source("good.txt", "admin\nbackup\n")
        add_custom_list(self.params, "my-list", src)
        add_custom_list(self.params, "my-list", src)
        doc = load_yaml_file(str(self.root / "wordlists" / "custom" / "index.yaml"))
        self.assertEqual(len(doc["lists"]), 1)

    def test_reject_bad_names(self):
        src = self._write_source("x.txt", "a\n")
        for bad in ("../evil", "/abs", "UPPER", "a", "with space"):
            with self.assertRaises(CustomListError):
                add_custom_list(self.params, bad, src)

    def test_reject_empty_and_secrets_and_charset(self):
        with self.assertRaises(CustomListError):
            add_custom_list(self.params, "empty", self._write_source("e.txt", ""))
        fake_pat = "github_pat_" + "11BC" + "T" * 40
        with self.assertRaises(CustomListError):
            add_custom_list(self.params, "leak", self._write_source("l.txt", "ok\n" + fake_pat + "\n"))
        with self.assertRaises(CustomListError):
            add_custom_list(self.params, "junk", self._write_source("j.txt", "ok\nbad path with spaces\n"))

    def test_remove_and_protection(self):
        src = self._write_source("g.txt", "alpha\n")
        add_custom_list(self.params, "removeme", src)
        self.assertIn("removeme", list_custom_lists(self.params))
        remove_custom_list(self.params, "removeme")
        self.assertNotIn("removeme", list_custom_lists(self.params))
        with self.assertRaises(CustomListError):
            remove_custom_list(self.params, "platform_learned")
        with self.assertRaises(CustomListError):
            remove_custom_list(self.params, "never-existed")

    def test_normalize_law(self):
        self.assertEqual(normalize_lines("# comment\n\nwww \napi\n"), ["www", "api"])
        with self.assertRaises(CustomListError):
            normalize_lines("http://url.form\n")
        with self.assertRaises(CustomListError):
            normalize_lines("x" * 300)


class PlatformLearning(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_root(Path(self._tmp.name), None)
        self.params = Params(self.root)
        self.tdir = self.root / "recon" / "example.com"
        (self.tdir / "10_subdomains" / "passive").mkdir(parents=True)
        (self.tdir / "20_dns" / "dnsx").mkdir(parents=True)
        (self.tdir / "10_subdomains" / "ffuf").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _seed(self, passive, dnsr=None, ffuf=None):
        import json
        (self.tdir / "10_subdomains" / "passive" / "data.json").write_text(
            json.dumps({"candidates": passive}), encoding="utf-8")
        (self.tdir / "20_dns" / "dnsx" / "data.json").write_text(
            json.dumps({"resolved": dnsr or []}), encoding="utf-8")
        (self.tdir / "10_subdomains" / "ffuf" / "data.json").write_text(
            json.dumps({"hosts": ffuf or []}), encoding="utf-8")

    def test_ingest_adds_labels_once(self):
        self._seed(
            passive=[{"host": "api.example.com"}, {"host": "dev.example.com"}, {"host": "evil.org"}],
            dnsr=[{"host": "www.example.com"}, {"host": "example.com"}],
            ffuf=[{"fqdn": "x.dev.example.com"}],
        )
        ledger = ingest_learned_labels(self.params, self.tdir, "example.com")
        self.assertEqual(ledger["added"], 4)
        learned = self.root / "wordlists" / "custom" / "platform-learned.txt"
        labels = learned.read_text(encoding="utf-8").split()
        self.assertEqual(sorted(labels), ["api", "dev", "www", "x.dev"])
        ledger2 = ingest_learned_labels(self.params, self.tdir, "example.com")
        self.assertEqual(ledger2["added"], 0)
        self.assertEqual(ledger2["total"], 4)

    def test_scope_law_blocks_foreign(self):
        self._seed(passive=[{"host": "other.example.com.evil.io"}])
        ledger = ingest_learned_labels(self.params, self.tdir, "example.com")
        self.assertEqual(ledger["added"], 0)

    def test_ensure_idempotent_and_selectable(self):
        ensure_learned_list(self.params)
        ensure_learned_list(self.params)
        doc = load_yaml_file(str(self.root / "wordlists" / "custom" / "index.yaml"))
        self.assertIn("platform_learned", doc["lists"])
        reg = WordlistRegistry(self.params)
        self.assertIn("platform_learned", reg.allowed_keys("FFUF-0"))


if __name__ == "__main__":
    unittest.main()
