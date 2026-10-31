"""CSV / TXT domain-file parsing."""
from gandoki.discovery.file_input import (
    load_csv, load_domains_file, load_txt, merge_load_results,
    parse_single_url,
)


def test_txt_basic(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text(
        "# comment\n"
        "example.com\n"
        "https://app.example.com/path\n"
        "bad entry\n"
        "example.com\n"
        "www.foo.org\n"
    )
    r = load_txt(p)
    assert "example.com" in r.domains
    assert "app.example.com" in r.domains
    assert "foo.org" in r.domains
    assert r.skipped_duplicates == 1
    assert "bad entry" in r.skipped_invalid


def test_csv_with_header(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("website,owner\nhttps://a.example.com,me\nb.example.org,me\n")
    r = load_csv(p)
    assert set(r.domains) == {"a.example.com", "b.example.org"}


def test_csv_no_header(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("a.example.com,x\nb.example.org,y\n")
    r = load_csv(p)
    assert set(r.domains) == {"a.example.com", "b.example.org"}


def test_semicolon_csv(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("domain;owner\na.example.com;me\n")
    r = load_csv(p)
    assert r.domains == ["a.example.com"]


def test_dispatch_by_extension(tmp_path):
    p = tmp_path / "t.csv"
    p.write_text("website\nx.example.com\n")
    r = load_domains_file(p)
    assert r.domains == ["x.example.com"]


def test_merge_dedups_across_files(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("x.com\ny.com\n")
    b.write_text("y.com\nz.com\n")
    merged = merge_load_results([load_txt(a), load_txt(b)])
    assert merged.domains == ["x.com", "y.com", "z.com"]
    assert merged.skipped_duplicates == 1


def test_parse_single_url():
    host, seed = parse_single_url("https://app.example.com/admin/x?q=1")
    assert host == "app.example.com"
    assert seed.startswith("https://app.example.com/admin/x")

    host2, _ = parse_single_url("example.com")
    assert host2 == "example.com"

    bad_host, _ = parse_single_url("not a url")
    assert bad_host is None
