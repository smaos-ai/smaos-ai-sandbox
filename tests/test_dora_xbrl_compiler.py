import zipfile
import pytest
from src.dora_xbrl_compiler import (
    DORAXBRLCompiler,
    validate_iso17442_lei,
    compile_and_validate_dora_package,
    DORA_TEMPLATES
)

def test_iso17442_lei_validation():
    # Valid LEI with MOD 97 == 1
    assert validate_iso17442_lei("549300TRUWO2CD2G5692") is True
    assert validate_iso17442_lei("315700SOVEREIGNX0050") is True

    # Invalid length or characters
    assert validate_iso17442_lei("INVALID_LEI") is False
    assert validate_iso17442_lei("549300TRUWO2CD2G5692_EXTRA") is False

    # Invalid check digits
    assert validate_iso17442_lei("549300TRUWO2CD2G5699") is False

def test_dora_compiler_15_templates(tmp_path):
    out_dir = tmp_path / "standards_mapping"
    zip_path = tmp_path / "dora_register.zip"

    compiler = DORAXBRLCompiler(output_dir=str(out_dir))
    compiler.populate_production_dataset()

    assert len(compiler.tables) == 15
    for tmpl in DORA_TEMPLATES:
        assert tmpl in compiler.tables

    # Validation must pass cleanly
    val_report = compiler.validate_referential_integrity()
    assert val_report["status"] == "VALID"
    assert len(val_report["errors"]) == 0

    # Package into ZIP
    z_file = compiler.compile_package_zip(zip_path=str(zip_path))
    assert z_file.exists()

    with zipfile.ZipFile(z_file, "r") as z:
        names = z.namelist()
        assert "report-package.json" in names
        assert len(names) == 16  # 15 tables + 1 manifest
        # Test CRC
        assert z.testzip() is None

def test_dora_orphan_detection(tmp_path):
    compiler = DORAXBRLCompiler(output_dir=str(tmp_path))
    compiler.populate_production_dataset()

    # Introduce orphan ContractRef in RT.04.01
    compiler.tables["RT.04.01"][0]["ContractRef"] = "ORPHAN-CONTRACT-999"

    val_report = compiler.validate_referential_integrity()
    assert val_report["status"] == "INVALID"
    assert any("ORPHAN-CONTRACT-999" in err for err in val_report["errors"])
