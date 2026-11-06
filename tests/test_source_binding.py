"""Regression tests for safe selector->source binding (defect B) and the
explorer fallback classification (defect A). Offline: explorer_call mocked."""
import json
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from faultseeker.utils import explorer_provider
from faultseeker.utils.source_binding import (
    function_selector, canonical_signature, canonical_abi_type,
    parse_source_units, bind_function, is_selector, UnresolvableType,
)
from faultseeker.data_collection.contract_downloader import ContractDownloader


# ── selector / canonicalization vectors (Solidity docs) ──────────────────────

def test_known_selector_vectors():
    assert function_selector('baz', [{'type': 'uint32'}, {'type': 'bool'}]) == '0xcdcd77c0'
    assert function_selector('transfer', [{'type': 'address'}, {'type': 'uint256'}]) == '0xa9059cbb'
    assert function_selector('balanceOf', [{'type': 'address'}]) == '0x70a08231'
    assert function_selector('f', [{'type': 'uint256'}, {'type': 'uint32[]'},
                                   {'type': 'bytes10'}, {'type': 'bytes'}]) == '0x8be65246'
    assert function_selector('sam', [{'type': 'bytes'}, {'type': 'bool'},
                                     {'type': 'uint256[]'}]) == '0xa5643bf2'


def test_uint_and_names_excluded():
    assert canonical_signature('foo', [{'type': 'uint', 'name': 'x'}]) == 'foo(uint256)'
    assert canonical_signature('foo', [{'type': 'uint', 'name': 'x'}]) == \
           canonical_signature('foo', [{'type': 'uint', 'name': 'different'}])


def test_nested_tuple_with_array():
    sig = canonical_signature('g', [{
        'type': 'tuple',
        'components': [
            {'type': 'uint256'},
            {'type': 'tuple[]', 'components': [{'type': 'address'}, {'type': 'uint256[]'}]},
        ],
    }])
    assert sig == 'g((uint256,(address,uint256[])[]))'
    # selectors must be keccak-256 of the canonical string (8be... style check via length/hex)
    sel = function_selector('g', [{
        'type': 'tuple',
        'components': [
            {'type': 'uint256'},
            {'type': 'tuple[]', 'components': [{'type': 'address'}, {'type': 'uint256[]'}]},
        ],
    }])
    assert sel.startswith('0x') and len(sel) == 10


def test_tuple_without_components_fails_closed():
    with pytest.raises(UnresolvableType):
        canonical_abi_type({'type': 'tuple[]'})


# ── source bundle fixtures ────────────────────────────────────────────────────

BASE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    struct Point { uint256 x; uint256 y; }
    function move(Point memory p) public virtual returns (bool) {
        p.x;
        return true;
    }
}
"""

DERIVED_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import './Base.sol';

contract Derived is Base {
    struct Point { uint256 x; uint256 y; }
    function move(Point memory p) public override returns (bool) {
        p.y;
        return false;
    }
    function ping(uint256 a, uint256 b) public returns (uint256) {
        return a + b;
    }
    function ping(uint256 a) public returns (uint256) {
        return a;
    }
}
"""

UNRELATED_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Unrelated {
    struct Point { uint256 x; uint256 y; }
    function move(Point memory p) public returns (bool) {
        return false;
    }
    function orphan() public returns (uint256) { return 7; }
}
"""

INTERFACE_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IMove {
    struct Point { uint256 x; uint256 y; }
    function move(Point memory p) external returns (bool);
}

abstract contract AbstractMove {
    struct Point { uint256 x; uint256 y; }
    function move(Point memory p) public virtual returns (bool);
}
"""

MOVE_ABI = [{
    'type': 'function', 'name': 'move',
    'inputs': [{'name': 'p', 'type': 'tuple', 'internalType': 'struct Base.Point',
                'components': [{'name': 'x', 'type': 'uint256'}, {'name': 'y', 'type': 'uint256'}]}],
    'outputs': [{'name': '', 'type': 'bool'}],
}]
MOVE_SEL = function_selector('move', MOVE_ABI[0]['inputs'])


def _parsed(sources):
    parsed = parse_source_units(sources)
    lines = {p: c.split('\n') for p, c in sources.items()}
    return parsed, lines


def _bundle(contract_name, abi, proxy=False):
    return {'contract_name': contract_name, 'abi': abi, 'proxy': proxy, 'sources': {}}


def test_is_selector():
    assert is_selector('0xefd86b62')
    assert not is_selector('move')
    assert not is_selector('0xZZZ')
    assert not is_selector(None)


def test_override_binds_most_derived():
    sources = {'Base.sol': BASE_SRC, 'Derived.sol': DERIVED_SRC}
    parsed, lines = _parsed(sources)
    res = bind_function(_bundle('Derived', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'direct_verified'
    assert len(res['bodies']) == 1
    assert res['bodies'][0]['contract'] == 'Derived'
    assert 'return false' in res['bodies'][0]['content']


def test_inherited_binds_unique_ancestor():
    sources = {'Base.sol': BASE_SRC, 'Derived.sol': DERIVED_SRC, 'Unrelated.sol': UNRELATED_SRC}
    parsed, lines = _parsed(sources)
    # contract that inherits Base but does not override move
    src = dict(sources)
    src['Child.sol'] = ("pragma solidity ^0.8.0;\nimport './Base.sol';\n"
                        "contract Child is Base { function z() public returns (uint256) { return 1; } }\n")
    parsed, lines = _parsed(src)
    res = bind_function(_bundle('Child', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'inherited_verified'
    assert res['bodies'][0]['contract'] == 'Base'
    assert 'return true' in res['bodies'][0]['content']


def test_overloads_bind_distinct_bodies():
    sources = {'Derived.sol': DERIVED_SRC}
    abi = [
        {'type': 'function', 'name': 'ping', 'inputs': [{'name': 'a', 'type': 'uint256'}], 'outputs': []},
        {'type': 'function', 'name': 'ping', 'inputs': [{'name': 'a', 'type': 'uint256'},
                                                        {'name': 'b', 'type': 'uint256'}], 'outputs': []},
    ]
    parsed, lines = _parsed(sources)
    sel1 = function_selector('ping', abi[0]['inputs'])
    sel2 = function_selector('ping', abi[1]['inputs'])
    assert sel1 != sel2
    r1 = bind_function(_bundle('Derived', abi), parsed, sel1, lines)
    r2 = bind_function(_bundle('Derived', abi), parsed, sel2, lines)
    assert r1['status'] == r2['status'] == 'direct_verified'
    assert 'return a;' in r1['bodies'][0]['content']
    assert 'return a + b;' in r2['bodies'][0]['content']


def test_same_name_unrelated_contract_no_bind():
    sources = {'Unrelated.sol': UNRELATED_SRC, 'Empty.sol':
               "pragma solidity ^0.8.0;\ncontract Empty { function z() public returns (uint256) { return 1; } }\n"}
    parsed, lines = _parsed(sources)
    res = bind_function(_bundle('Empty', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'no_executable_body'


def test_selector_collision_fails_closed():
    sources = {'Derived.sol': DERIVED_SRC}
    dup = {'type': 'function', 'name': 'ping', 'inputs': [{'name': 'a', 'type': 'uint256'}], 'outputs': []}
    abi = [dict(dup), dict(dup)]
    parsed, lines = _parsed(sources)
    sel = function_selector('ping', dup['inputs'])
    res = bind_function(_bundle('Derived', abi), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'selector_collision_in_abi'


def test_interface_and_abstract_declarations_not_bodies():
    sources = {'IMove.sol': INTERFACE_SRC}
    parsed, lines = _parsed(sources)
    res = bind_function(_bundle('IMove', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] in ('no_executable_body', 'contract_not_in_source')
    res2 = bind_function(_bundle('AbstractMove', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res2['status'] == 'unresolved'


def test_proxy_fails_closed():
    parsed, lines = _parsed({'Base.sol': BASE_SRC})
    res = bind_function(_bundle('Base', MOVE_ABI, proxy=True), parsed, MOVE_SEL, lines)
    assert res['status'] == 'proxy_implementation'
    assert res['bodies'] == []


def test_selector_not_in_abi():
    parsed, lines = _parsed({'Base.sol': BASE_SRC})
    res = bind_function(_bundle('Base', MOVE_ABI), parsed, '0xdeadbeef', lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'selector_not_in_abi'


# ── bundle normalization (Etherscan + Blockscout shapes) ─────────────────────

def _fake_call_factory(payload):
    def fake(chain, params, timeout=20):
        return payload
    return fake


def test_bundle_blockscout_shape(monkeypatch):
    payload = {'status': '1', 'message': 'OK', 'result': [{
        'SourceCode': BASE_SRC,
        'AdditionalSources': [{'SourceCode': DERIVED_SRC, 'Filename': 'Derived.sol'}],
        'ContractName': 'Base',
        'FileName': 'Base.sol',
        'ABI': json.dumps(MOVE_ABI),
    }]}
    monkeypatch.setattr('faultseeker.data_collection.contract_downloader.explorer_call',
                        _fake_call_factory(payload))
    b = ContractDownloader.get_source_bundle('eth', '0xabc')
    assert b['contract_name'] == 'Base'
    assert 'Base.sol' in b['sources'] and 'Derived.sol' in b['sources']
    assert isinstance(b['abi'], list) and b['proxy'] is False


def test_bundle_etherscan_multifile_shape(monkeypatch):
    multi = '{' + json.dumps({'language': 'Solidity', 'sources': {'A.sol': {'content': '{a}'}}}) + '}'
    payload = {'status': '1', 'message': 'OK', 'result': [{
        'SourceCode': multi, 'ContractName': 'A', 'ABI': '[]',
    }]}
    monkeypatch.setattr('faultseeker.data_collection.contract_downloader.explorer_call',
                        _fake_call_factory(payload))
    b = ContractDownloader.get_source_bundle('eth', '0xabc')
    assert b['sources'] == {'A.sol': '{a}'}


def test_bundle_failure_is_explicit_not_empty(monkeypatch):
    monkeypatch.setattr('faultseeker.data_collection.contract_downloader.explorer_call',
                        _fake_call_factory(None))
    assert ContractDownloader.get_source_bundle('eth', '0xabc') is None
    monkeypatch.setattr('faultseeker.data_collection.contract_downloader.explorer_call',
                        _fake_call_factory({'status': '0', 'message': 'NOTOK', 'result': 'Missing/Invalid API Key'}))
    assert ContractDownloader.get_source_bundle('eth', '0xabc') is None


# ── explorer auth classification / failover ───────────────────────────────────

def test_notok_missing_key_classified_as_auth_and_fails_over(monkeypatch):
    calls = []

    class FakeResp:
        def __init__(self, payload):
            self.payload = payload
        def read(self):
            return json.dumps(self.payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=20):
        calls.append(req.full_url)
        if 'api.etherscan.io' in req.full_url:
            return FakeResp({'status': '0', 'message': 'NOTOK',
                             'result': 'Missing/Invalid API Key, visit https://etherscan.io/myapikey'})
        return FakeResp({'status': '1', 'message': 'OK', 'result': 'fine'})

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    out = explorer_provider.explorer_call('eth', {'module': 'contract', 'action': 'getabi', 'address': '0xabc'})
    assert out == {'status': '1', 'message': 'OK', 'result': 'fine'}
    assert any('eth.blockscout.com' in u for u in calls)


def test_rate_limit_result_classified(monkeypatch):
    class FakeResp:
        def __init__(self, payload):
            self.payload = payload
        def read(self):
            return json.dumps(self.payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    seen = []

    def fake_urlopen(req, timeout=20):
        seen.append(req.full_url)
        if 'api.etherscan.io' in req.full_url:
            return FakeResp({'status': '0', 'message': 'NOTOK',
                             'result': 'Max rate limit reached, please use API Key for higher rate limit'})
        return FakeResp({'status': '1', 'message': 'OK', 'result': 'fine'})

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    out = explorer_provider.explorer_call('eth', {'module': 'contract', 'action': 'getabi', 'address': '0xabc'})
    assert out['status'] == '1'


# ── analyzer wiring: plain-name regression + selector path ───────────────────

class _FakeAnalyzer:
    from faultseeker.function_analysis.function_analyzer import FunctionAnalyzer as _FA
    _retrieve_source_code = _FA._retrieve_source_code
    _binding_for_address = _FA._binding_for_address

    def __init__(self, chain='eth'):
        class AR:
            pass
        self.analysis_result = AR()
        self.analysis_result.chain = chain
        self.contract_info = {}


def test_plain_name_path_unchanged(monkeypatch):
    fa = _FakeAnalyzer()
    fa.contract_info['0xabc'] = {'move': [{'path': './Implementation/Base.sol',
                                           'start_line': 1, 'end_line': 3,
                                           'content': 'function move...'}]}
    out = fa._retrieve_source_code('0xabc', 'move')
    assert len(out) == 1 and out[0]['source_code'] == 'function move...'


def test_selector_path_via_binding(monkeypatch):
    sources = {'Base.sol': BASE_SRC}
    bundle = {'contract_name': 'Base', 'abi': MOVE_ABI, 'proxy': False, 'sources': sources}
    monkeypatch.setattr(ContractDownloader, 'get_source_bundle', staticmethod(lambda c, a: bundle))
    fa = _FakeAnalyzer()
    out = fa._retrieve_source_code('0xabc', MOVE_SEL)
    assert len(out) == 1
    assert out[0]['binding'] == 'direct_verified'
    assert 'function move' in out[0]['source_code']


def test_selector_path_sourceless_explicit(monkeypatch):
    monkeypatch.setattr(ContractDownloader, 'get_source_bundle', staticmethod(lambda c, a: None))
    fa = _FakeAnalyzer()
    assert fa._retrieve_source_code('0xabc', MOVE_SEL) == []
    # cached failure: second call must not re-fetch
    calls = []
    monkeypatch.setattr(ContractDownloader, 'get_source_bundle',
                        staticmethod(lambda c, a: calls.append(1)))
    assert fa._retrieve_source_code('0xabc', MOVE_SEL) == []
    assert calls == []


def test_empty_body_override_binds_override_not_base():
    """An empty {} override is an executable body: it must hide the base body."""
    src = {'Base.sol': BASE_SRC,
           'Empty.sol': ("pragma solidity ^0.8.0;\nimport './Base.sol';\n"
                         "contract EmptyOverride is Base {\n"
                         "    struct Point { uint256 x; uint256 y; }\n"
                         "    function move(Point memory p) public override returns (bool) {}\n"
                         "}\n")}
    parsed, lines = _parsed(src)
    res = bind_function(_bundle('EmptyOverride', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'direct_verified'
    assert res['bodies'][0]['contract'] == 'EmptyOverride'
    assert 'return true' not in res['bodies'][0]['content']


def test_duplicate_contract_declaration_fails_closed():
    """Two source units declaring the same contract name: never bind the
    surviving-overwrite body."""
    src = {'A.sol': "pragma solidity ^0.8.0;\ncontract Dup { function z() public returns (uint256) { return 1; } }\n",
           'B.sol': "pragma solidity ^0.8.0;\ncontract Dup { function z() public returns (uint256) { return 2; } }\n"}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'z', 'inputs': [], 'outputs': []}]
    sel = function_selector('z', [])
    res = bind_function(_bundle('Dup', abi), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'duplicate_contract_declarations'


def test_ambiguous_ancestor_fails_closed():
    """Lineage through a duplicated base name cannot prove the effective
    implementation; fail closed rather than bind either candidate."""
    src = {'Base.sol': BASE_SRC,
           'LibA.sol': "pragma solidity ^0.8.0;\ncontract Shared { struct Point { uint256 x; uint256 y; } function move(Point memory p) public returns (bool) { return true; } }\n",
           'LibB.sol': "pragma solidity ^0.8.0;\ncontract Shared { struct Point { uint256 x; uint256 y; } function move(Point memory p) public returns (bool) { return false; } }\n",
           'Child.sol': "pragma solidity ^0.8.0;\nimport './LibA.sol';\ncontract Child is Shared { function z() public returns (uint256) { return 1; } }\n"}
    parsed, lines = _parsed(src)
    res = bind_function(_bundle('Child', MOVE_ABI), parsed, MOVE_SEL, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'duplicate_contract_declarations'


def test_ambiguous_file_level_struct_fails_closed():
    """Same simple struct name with different layouts in two source units:
    signature identity cannot be proven; binding must fail closed."""
    src = {'A.sol': ("pragma solidity ^0.8.0;\nstruct Cfg { uint256 a; }\n"
                     "contract Target { function setup(Cfg memory c) public returns (uint256) { return c.a; } }\n"),
           'B.sol': "pragma solidity ^0.8.0;\nstruct Cfg { uint256 a; address b; }\n"}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'setup',
            'inputs': [{'name': 'c', 'type': 'tuple', 'internalType': 'struct Cfg',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('setup', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'unresolved'


def test_identical_duplicate_struct_still_binds():
    """Flattened bundles legitimately repeat identical struct definitions;
    those dedupe and binding still succeeds."""
    src = {'A.sol': ("pragma solidity ^0.8.0;\nstruct Cfg { uint256 a; }\n"
                     "contract Target { function setup(Cfg memory c) public returns (uint256) { return c.a; } }\n"),
           'B.sol': "pragma solidity ^0.8.0;\nstruct Cfg { uint256 a; }\n"}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'setup',
            'inputs': [{'name': 'c', 'type': 'tuple', 'internalType': 'struct Cfg',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('setup', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'direct_verified'
    assert 'return c.a' in res['bodies'][0]['content']


def test_qualified_struct_resolves_named_namespace():
    src = {'B.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { struct S { uint256 a; } }\n"
                     "contract Target is Base {\n"
                     "    function f(Base.S memory s) public returns (uint256) { return 1; }\n"
                     "}\n")}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'f',
            'inputs': [{'name': 's', 'type': 'tuple', 'internalType': 'struct Base.S',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('f', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'direct_verified'
    assert 'return 1' in res['bodies'][0]['content']


def test_same_layout_overload_via_qualified_name_fails_closed():
    """f(Base.S) and f(S) with identical layouts produce the same canonical
    signature; two executable bodies match, so binding must fail closed."""
    src = {'B.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { struct S { uint256 a; } }\n"
                     "contract Target is Base {\n"
                     "    struct S { uint256 a; }\n"
                     "    function f(Base.S memory s) public returns (uint256) { return 1; }\n"
                     "    function f(S memory s) public returns (uint256) { return 2; }\n"
                     "}\n")}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'f',
            'inputs': [{'name': 's', 'type': 'tuple', 'internalType': 'struct Base.S',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('f', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'multiple_bodies_in_contract'


def test_unresolvable_direct_override_fails_closed_not_inherited():
    """A derived contract declaring the same function name shadows the base
    (Solidity name hiding). If the direct signature cannot be resolved, the
    answer must be unresolved - never the ancestor's body."""
    src = {'B.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { struct S { uint256 a; } function f(S memory s) public returns (uint256) { return 1; } }\n"
                     "contract Target is Base {\n"
                     "    function f(Mystery.S memory s) public returns (uint256) { return 2; }\n"
                     "}\n")}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'f',
            'inputs': [{'name': 's', 'type': 'tuple', 'internalType': 'struct Base.S',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('f', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'] == 'unresolvable_direct_signature'


def test_import_alias_qualified_struct_binds_direct():
    """import * as Lib; Child is Lib.Base; override f(Lib.Base.S): the qualified
    struct resolves through the alias's simple contract name and binds the
    direct override body."""
    src = {'B.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { struct S { uint256 a; } function f(S memory s) public returns (uint256) { return 1; } }\n"),
           'C.sol': ("pragma solidity ^0.8.0;\nimport * as Lib from './B.sol';\n"
                     "contract Target is Lib.Base {\n"
                     "    function f(Lib.Base.S memory s) public returns (uint256) { return 2; }\n"
                     "}\n")}
    parsed, lines = _parsed(src)
    abi = [{'type': 'function', 'name': 'f',
            'inputs': [{'name': 's', 'type': 'tuple', 'internalType': 'struct Base.S',
                        'components': [{'name': 'a', 'type': 'uint256'}]}],
            'outputs': []}]
    sel = function_selector('f', abi[0]['inputs'])
    res = bind_function(_bundle('Target', abi), parsed, sel, lines)
    assert res['status'] == 'direct_verified'
    assert 'return 2' in res['bodies'][0]['content']


F_UINT_ABI = [{'type': 'function', 'name': 'f',
               'inputs': [{'name': 'x', 'type': 'uint256'}], 'outputs': []}]


def test_import_aliased_base_uses_import_identity_not_global_name():
    """Reviewer case: import {Base as B}; contract Target is B {}. The alias B
    must resolve through the import to Base.sol::Base - never to the unrelated
    global Other.sol::B - even with NO direct body on Target."""
    src = {
        'Base.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { function f(uint256 x) public returns (uint256) { return 1; } }\n"),
        'Other.sol': ("pragma solidity ^0.8.0;\n"
                      "contract B { function f(uint256 x) public returns (uint256) { return 999; } }\n"),
        'Target.sol': ("pragma solidity ^0.8.0;\nimport {Base as B} from './Base.sol';\n"
                       "contract Target is B {}\n"),
    }
    parsed, lines = _parsed(src)
    sel = function_selector('f', F_UINT_ABI[0]['inputs'])
    res = bind_function(_bundle('Target', F_UINT_ABI), parsed, sel, lines)
    assert res['status'] == 'inherited_verified'
    assert res['bodies'][0]['contract'] == 'Base'
    assert 'return 1' in res['bodies'][0]['content']


def test_import_alias_missing_file_fails_closed():
    """Aliased base whose imported file is not in the bundle: unsupported
    ancestry must fail closed, never fall back to a same-named global."""
    src = {
        'Other.sol': ("pragma solidity ^0.8.0;\n"
                      "contract B { function f(uint256 x) public returns (uint256) { return 999; } }\n"),
        'Target.sol': ("pragma solidity ^0.8.0;\nimport {Base as B} from './Missing.sol';\n"
                       "contract Target is B {}\n"),
    }
    parsed, lines = _parsed(src)
    sel = function_selector('f', F_UINT_ABI[0]['inputs'])
    res = bind_function(_bundle('Target', F_UINT_ABI), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'].startswith('unsupported_ancestry')


def test_qualified_base_without_import_alias_fails_closed():
    """contract Target is Lib.Base {} with no `import * as Lib` in scope:
    qualifier stripping could bind an unrelated Base, so fail closed."""
    src = {
        'Base.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { function f(uint256 x) public returns (uint256) { return 1; } }\n"),
        'Target.sol': ("pragma solidity ^0.8.0;\n"
                       "contract Target is Lib.Base {}\n"),
    }
    parsed, lines = _parsed(src)
    sel = function_selector('f', F_UINT_ABI[0]['inputs'])
    res = bind_function(_bundle('Target', F_UINT_ABI), parsed, sel, lines)
    assert res['status'] == 'unresolved'
    assert res['reason'].startswith('unsupported_ancestry')


def test_commented_import_alias_does_not_overwrite_real_alias():
    """Reviewer case: a LINE COMMENT holding `import {Other as B}` must not
    overwrite the real `import {Base as B}` - imports come from parse tokens,
    never raw text."""
    src = {
        'Base.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { function f(uint256 x) public returns (uint256) { return 1; } }\n"),
        'Other.sol': ("pragma solidity ^0.8.0;\n"
                      "contract B { function f(uint256 x) public returns (uint256) { return 999; } }\n"),
        'Target.sol': ("pragma solidity ^0.8.0;\nimport {Base as B} from './Base.sol';\n"
                       "//import {Other as B} from './Other.sol';\n"
                       "contract Target is B {}\n"),
    }
    parsed, lines = _parsed(src)
    sel = function_selector('f', F_UINT_ABI[0]['inputs'])
    res = bind_function(_bundle('Target', F_UINT_ABI), parsed, sel, lines)
    assert res['status'] == 'inherited_verified'
    assert res['bodies'][0]['contract'] == 'Base'
    assert 'return 1' in res['bodies'][0]['content']


def test_block_comment_and_string_import_text_are_not_imports():
    """Block comments and string literals containing import-like text are not
    import directives."""
    src = {
        'Base.sol': ("pragma solidity ^0.8.0;\n"
                     "contract Base { function f(uint256 x) public returns (uint256) { return 1; } }\n"),
        'Other.sol': ("pragma solidity ^0.8.0;\n"
                      "contract B { function f(uint256 x) public returns (uint256) { return 999; } }\n"),
        'Target.sol': ("pragma solidity ^0.8.0;\nimport {Base as B} from './Base.sol';\n"
                       "/* import {Other as B} from './Other.sol'; */\n"
                       "contract Target is B {\n"
                       "    string constant NOTE = \"import {Other as B} from './Other.sol';\";\n"
                       "}\n"),
    }
    parsed, lines = _parsed(src)
    sel = function_selector('f', F_UINT_ABI[0]['inputs'])
    res = bind_function(_bundle('Target', F_UINT_ABI), parsed, sel, lines)
    assert res['status'] == 'inherited_verified'
    assert res['bodies'][0]['contract'] == 'Base'
    assert 'return 1' in res['bodies'][0]['content']
