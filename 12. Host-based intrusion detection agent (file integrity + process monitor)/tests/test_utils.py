from hids.core.utils import path_excluded, sha256_file


def test_path_excluded_wildcards():
    pats = ["*.log", "*/.git/*", "*/node_modules/*"]
    assert path_excluded("C:/app/logs/error.log", pats)
    assert path_excluded(r"C:\repo\.git\objects\ab\cd", pats)
    assert path_excluded(r"C:\web\node_modules\pkg\index.js", pats)
    assert not path_excluded("C:/app/config.ini", pats)


def test_path_excluded_dir_prefix():
    pats = ["C:/Windows/Temp/"]
    assert path_excluded(r"C:\Windows\Temp\evil.exe", pats)
    assert path_excluded("C:/Windows/Temp/evil.exe", pats)
    assert not path_excluded(r"C:\Windows\System32\cmd.exe", pats)


def test_path_excluded_bare_name():
    pats = ["pagefile.sys"]
    assert path_excluded(r"C:\pagefile.sys", pats)
    assert path_excluded("D:/pagefile.sys", pats)
    assert not path_excluded("C:/pagefile.sys.bak", pats)


def test_sha256_file(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hello")
    digest = sha256_file(f)
    assert digest == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert sha256_file(tmp_path / "missing.txt") is None
    assert sha256_file(f, max_bytes=2) is None  # too large -> None
