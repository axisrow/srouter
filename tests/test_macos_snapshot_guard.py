import importlib.util
from pathlib import Path

import pytest


def snapshot_module():
    source = Path(__file__).parent / 'macos/snapshot.py'
    spec = importlib.util.spec_from_file_location('vm_snapshot_guard_test', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('opt_in,model', [(False, 'VirtualMac2,1'), (True, 'Mac14,2')])
def test_snapshot_requires_opt_in_and_virtual_hardware(monkeypatch, tmp_path, opt_in, model):
    module = snapshot_module()
    monkeypatch.setenv('SROUTER_VM_ACCEPTANCE', '1' if opt_in else '0')
    calls = []
    def read(cmd, *a, **k):
        calls.append(cmd)
        assert cmd == ['/usr/sbin/sysctl', '-n', 'hw.model']
        return {'rc': 0, 'out': model, 'err': ''}
    monkeypatch.setattr(module, 'run', read)
    with pytest.raises(SystemExit, match='REFUSED'):
        module.snapshot(tmp_path)
    assert len(calls) == 1
