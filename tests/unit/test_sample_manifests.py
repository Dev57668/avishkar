import json

import pytest

from avishkar import samples


def _write(root, sid, manifest, files=None):
    d = root / sid
    d.mkdir(parents=True)
    (d / "sample.json").write_text(json.dumps(manifest), encoding="utf8")
    for name, text in (files or {"app.py": "x = 1\n"}).items():
        (d / name).write_text(text, encoding="utf8")


GOOD = {"name": "Good", "language": "Python", "kind": "vulnerable", "description": "d", "expected": "e",
        "fixes": [{"id": "fx-one", "title": "t", "file": "app.py", "removes": [], "explanation": "x", "edits": [["x = 1", "x = 2"]]}]}


@pytest.fixture()
def fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(samples, "SAMPLES_DIR", tmp_path)
    monkeypatch.setattr(samples, "SAMPLES", {})
    return tmp_path


def test_manifest_sample_is_discovered_and_its_fix_applies(fresh):
    _write(fresh, "my-sample", GOOD)
    samples._discover()
    s = samples.SAMPLES["my-sample"]
    assert s.kind == "vulnerable" and [f.id for f in s.fixes] == ["fx-one"]
    assert samples.variant_files("my-sample", ["fx-one"])["app.py"] == "x = 2\n"
    assert "sample.json" not in samples.variant_files("my-sample")  # the manifest itself is never scanned


@pytest.mark.parametrize("manifest", [
    {**GOOD, "kind": "weird"},
    {**GOOD, "fixes": GOOD["fixes"] * 2},                                   # duplicate fix ids
    {**GOOD, "fixes": [{**GOOD["fixes"][0], "id": "Bad_Id!"}]},             # unsafe fix id
    {k: v for k, v in GOOD.items() if k != "name"},                         # missing field
])
def test_malformed_manifests_are_skipped_not_half_loaded(fresh, manifest):
    _write(fresh, "broken", manifest)
    samples._discover()
    assert "broken" not in samples.SAMPLES


def test_bad_folder_names_and_non_json_are_ignored(fresh):
    _write(fresh, "Bad Name", GOOD)
    (fresh / "junk").mkdir()
    (fresh / "junk" / "sample.json").write_text("{not json", encoding="utf8")
    samples._discover()
    assert samples.SAMPLES == {}


def test_a_fix_whose_edit_no_longer_matches_is_rejected_at_use(fresh):
    _write(fresh, "drift", {**GOOD, "fixes": [{**GOOD["fixes"][0], "edits": [["not present", "y"]]}]})
    samples._discover()
    with pytest.raises(samples.SampleError):
        samples.variant_files("drift", ["fx-one"])


def test_built_in_samples_win_over_a_manifest_with_the_same_name(fresh, monkeypatch):
    monkeypatch.setitem(samples.SAMPLES, "dup", samples.Sample("dup", "Built-in", "Python", "secure", "dup", "d", "e"))
    _write(fresh, "dup", GOOD)
    samples._discover()
    assert samples.SAMPLES["dup"].name == "Built-in"
