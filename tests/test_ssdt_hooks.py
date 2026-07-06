from volguard.core.data_models import SsdtEntry
from volguard.plugins.ssdt_hooks import detect_ssdt_hooks


def test_ssdt_out_of_range_triggers():
    entries = [
        SsdtEntry(index=1, addr=0x500000, expected_module_base=0x0),
        SsdtEntry(index=2, addr=0x1000, expected_module_base=0x1000),
    ]
    f = detect_ssdt_hooks(entries)
    assert any(x.tags == ["ssdt", "hook"] for x in f)
