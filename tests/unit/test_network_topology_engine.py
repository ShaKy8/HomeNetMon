"""The topology engine's dependency tree (the method was referenced but never defined)."""

from types import SimpleNamespace

from services.network_topology import NetworkTopologyEngine


def _dev(i, ip, name, dtype='computer'):
    return SimpleNamespace(id=i, ip_address=ip, display_name=name, device_type=dtype)


def test_dependency_tree_nests_hierarchy_under_roots():
    engine = NetworkTopologyEngine()
    devices = [_dev(1, '192.168.1.1', 'gateway', 'router'), _dev(2, '192.168.1.2', 'switch', 'switch'),
               _dev(3, '192.168.1.30', 'pc'), _dev(4, '192.168.1.40', 'lonely')]
    relationships = {'parent_child': {
        'root_devices': [{'device_id': 1}],
        'hierarchy': {1: {'children': [{'device_id': 2}]}, 2: {'children': [{'device_id': 3}]}},
        'orphaned_devices': [{'device_id': 4}],
    }}
    tree = engine._build_dependency_tree(devices, relationships)
    assert [r['device_id'] for r in tree['roots']] == [1]
    assert tree['roots'][0]['children'][0]['device_id'] == 2
    assert tree['roots'][0]['children'][0]['children'][0]['device_name'] == 'pc'
    assert tree['max_depth'] == 2 and tree['devices_in_tree'] == 3 and tree['device_count'] == 4
    assert tree['orphaned_devices'][0]['ip_address'] == '192.168.1.40'


def test_dependency_tree_survives_cycles_and_empty_input():
    engine = NetworkTopologyEngine()
    devices = [_dev(1, '10.0.0.1', 'a'), _dev(2, '10.0.0.2', 'b')]
    cyclic = {'parent_child': {'root_devices': [{'device_id': 1}],
                               'hierarchy': {1: {'children': [{'device_id': 2}]}, 2: {'children': [{'device_id': 1}]}}}}
    tree = engine._build_dependency_tree(devices, cyclic)
    assert tree['roots'][0]['children'][0]['children'][0]['device_id'] == 1   # cycle terminated
    empty = engine._build_dependency_tree([], {})
    assert empty == {'roots': [], 'orphaned_devices': [], 'max_depth': 0, 'devices_in_tree': 0, 'device_count': 0}
