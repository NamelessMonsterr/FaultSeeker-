"""
source_binding.py — Safe selector -> function body binding for FaultSeeker.

The analyzer's model-facing function identity is (contract address, 4-byte
calldata selector). The source parser, however, indexes function bodies by
PLAIN NAME with no contract scope. Binding a selector to a plain name and then
taking the first body under that name is unsafe: overloaded functions share a
plain name, and unrelated contracts in one source bundle can share names too.

This module implements the minimal safe rule:

    requested address
        -> verified source bundle + ABI from the SAME explorer response
        -> selector -> canonical signature (exactly one ABI entry required)
        -> contract scope (explorer ContractName) + canonical signature
        -> exactly one executable body, else fail closed "unresolved"

Binding kinds: direct_verified | inherited_verified | proxy_implementation |
unresolved. Proxies are explicitly unresolved (the relevant implementation is
the one at the transaction's block/trace frame; resolving that is out of
scope). Selector->plain-name aliasing alone is NOT performed.

Canonical signature rules (Ethereum ABI):
  uint -> uint256, int -> int256, fixed -> fixed128x18, ufixed -> ufixed128x18,
  byte -> bytes1, enum -> uint8, contract/interface types -> address,
  tuple -> recursively expanded component types, tuple[]/tuple[N] keep their
  array suffixes, parameter names/returns/metadata excluded, Keccak-256
  (eth_utils.keccak), never hashlib.sha3_256.
Source-side user-defined structs are expanded through parsed struct
definitions (nested tuples and arrays supported); anything that cannot be
canonicalized fails closed.
"""

import json
import logging
import posixpath
import re

import antlr4
from eth_utils import keccak

from faultseeker.utils.solidityParser.antlrGenerated.SolidityLexer import SolidityLexer
from faultseeker.utils.solidityParser.antlrGenerated.SolidityParser import SolidityParser
from faultseeker.utils.solidityParser.antlrGenerated.SolidityListener import SolidityListener

log = logging.getLogger('faultseeker.source_binding')

_SELECTOR_RE = re.compile(r'^0x[0-9a-fA-F]{8}$')
_ARRAY_SUFFIX_RE = re.compile(r'(\[\d*\])+$')


class UnresolvableType(Exception):
    """A parameter type cannot be canonicalized; binding must fail closed."""


def is_selector(value) -> bool:
    return isinstance(value, str) and bool(_SELECTOR_RE.match(value.strip()))


# ── Canonical ABI typing ───────────────────────────────────────────────────────

def _canonical_elementary(t: str) -> str:
    t = t.strip()
    if t == 'uint':
        return 'uint256'
    if t == 'int':
        return 'int256'
    if t == 'fixed':
        return 'fixed128x18'
    if t == 'ufixed':
        return 'ufixed128x18'
    if t == 'byte':
        return 'bytes1'
    return t


def canonical_abi_type(param: dict) -> str:
    """Canonical ABI type for one ABI parameter (recursive tuple expansion)."""
    t = (param.get('type') or '').strip()
    suffix = ''
    m = _ARRAY_SUFFIX_RE.search(t)
    if m:
        suffix = m.group(0)
        t = t[:m.start()]
    internal = (param.get('internalType') or '').strip()
    if t == 'tuple':
        components = param.get('components')
        if not components:
            raise UnresolvableType(f'tuple without components: {param!r}')
        inner = ','.join(canonical_abi_type(c) for c in components)
        return f'({inner}){suffix}'
    base = _canonical_elementary(t)
    if base in ('uint8',) and internal.startswith('enum '):
        return f'uint8{suffix}'
    if base == 'address' or internal.startswith('contract ') or internal.startswith('interface '):
        return f'address{suffix}' if base == 'address' else f'{base}{suffix}'
    return f'{base}{suffix}'


def canonical_signature(name: str, inputs: list) -> str:
    return f"{name}({','.join(canonical_abi_type(p) for p in inputs)})"


def function_selector(name: str, inputs: list) -> str:
    """4-byte selector from the canonical signature, Keccak-256."""
    return '0x' + keccak(text=canonical_signature(name, inputs))[:4].hex()


# ── Scoped source parsing (ANTLR) ──────────────────────────────────────────────

class _ScopedListener(SolidityListener):
    """Collects contracts with bases, functions (params + body presence),
    structs and enums, preserving overloads and enclosing scope."""

    def __init__(self, path):
        self.path = path
        self.current_contract = None
        self.contracts = {}          # name -> {kind, bases, functions}
        self.structs = {}            # (contract|None, name) -> [member type texts]
        self.enums = set()           # (contract|None, name)
        self.contract_names = set()  # every contract/interface/library name

    # -- contracts --
    def enterContractDefinition(self, ctx):
        name = ctx.identifier().getText()
        kind = 'contract'
        if ctx.InterfaceKeyword():
            kind = 'interface'
        elif ctx.LibraryKeyword():
            kind = 'library'
        elif ctx.AbstractKeyword():
            kind = 'abstract'
        bases = []
        specs = ctx.inheritanceSpecifier()
        if specs:
            if not isinstance(specs, list):
                specs = [specs]
            for spec in specs:
                ip = getattr(spec, 'identifierPath', lambda: None)()
                base = ip.getText() if ip is not None else spec.getText().split('(')[0]
                # Keep the raw (possibly qualified / import-aliased) base
                # text: identity is resolved against the importing file's
                # import directives, never by qualifier stripping.
                bases.append(base)
        self.current_contract = name
        self.contract_names.add(name)
        self.contracts[name] = {'kind': kind, 'bases': bases, 'functions': {}, 'path': self.path}

    def exitContractDefinition(self, ctx):
        self.current_contract = None

    # -- functions --
    def enterFunctionDefinition(self, ctx):
        if self.current_contract is None or not ctx.identifier():
            return  # free functions / receive / fallback: not bindable
        name = ctx.identifier().getText()
        params = []
        plist = ctx.parameterList()
        if plist is not None:
            for p in plist.parameter():
                type_text = p.typeName().getText() if p.typeName() else ''
                params.append(type_text)
        # Any parsed block is an executable body - including an empty {} body,
        # which still overrides (and hides) an ancestor implementation.
        has_body = ctx.block() is not None
        start = ctx.start.line
        stop = ctx.stop.line if ctx.stop else ctx.start.line
        entry = {
            'name': name,
            'param_types': params,
            'has_body': has_body,
            'start_line': start,
            'end_line': stop,
            'path': self.path,
            'contract': self.current_contract,
        }
        self.contracts[self.current_contract]['functions'].setdefault(name, []).append(entry)

    # -- structs / enums (contract-scoped or file-level) --
    def enterStructDefinition(self, ctx):
        name = ctx.identifier().getText()
        members = []
        for vd in ctx.variableDeclaration():
            t = vd.typeName().getText() if vd.typeName() else ''
            members.append(t)
        self.structs[(self.current_contract, name)] = members

    def enterEnumDefinition(self, ctx):
        self.enums.add((self.current_contract, ctx.identifier().getText()))


def _parse_import_tokens(tokens) -> dict:
    """Extract import directives from a LEXED token stream.

    Token-level scanning is comment- and string-literal-safe: comment and
    string contents never become `import` tokens. (This grammar's lexer emits
    'from' as Identifier, so parse-tree importDirective rules error-recover
    and lose the path - the token stream is the reliable source.)
    Returns {'symbols': {alias: (path, orig)}, 'file_aliases': {alias: path},
    'plain': [path]}.
    """
    imports = {'symbols': {}, 'file_aliases': {}, 'plain': []}
    toks = [t for t in tokens.tokens if t.channel == 0 and t.type != -1]

    def text(i):
        return toks[i].text if 0 <= i < len(toks) else None

    i = 0
    while i < len(toks):
        if text(i) != 'import':
            i += 1
            continue
        j = i + 1
        try:
            if text(j) and text(j).startswith(("'", '"')) and len(text(j)) >= 2:
                # import "path";  /  import "path" as Q;
                path = text(j)[1:-1]
                if text(j + 1) == 'as' and text(j + 2):
                    imports['file_aliases'][text(j + 2)] = path
                else:
                    imports['plain'].append(path)
            elif text(j) in ('*',) or (text(j) and text(j) not in ('{',)):
                # import * as Q from "path";  /  import Q from "path";
                k = j + 1
                alias = None
                if text(j) == '*':
                    if text(k) == 'as':
                        alias = text(k + 1)
                        k += 2
                else:
                    if text(k) == 'as':
                        alias = text(k + 1)
                        k += 2
                    else:
                        alias = text(j)
                if text(k) == 'from' and text(k + 1) and text(k + 1).startswith(("'", '"')):
                    if alias:
                        imports['file_aliases'][alias] = text(k + 1)[1:-1]
            if text(j) == '{':
                k = j + 1
                decls = []
                while text(k) and text(k) != '}':
                    if text(k) == ',':
                        k += 1
                        continue
                    orig = text(k)
                    k += 1
                    if text(k) == 'as':
                        decls.append((text(k + 1), orig))
                        k += 2
                    else:
                        decls.append((orig, orig))
                # expect: } from "path"
                if text(k) == '}' and text(k + 1) == 'from' and text(k + 2) and text(k + 2).startswith(("'", '"')):
                    path = text(k + 2)[1:-1]
                    for alias, orig in decls:
                        imports['symbols'][alias] = (path, orig)
        except Exception:
            pass  # a malformed directive yields no identity, never a guess
        i += 1
    return imports


def parse_source_units(sources: dict) -> dict:
    """Parse {path: solidity code} -> scoped bundle structure."""
    listener = _ScopedListener(path='')
    combined = {'contracts': {}, 'structs': {}, 'enums': set(), 'contract_names': set(), 'imports': {},
                'sources_paths': set(sources.keys())}
    for path, code in sources.items():
        lis = _ScopedListener(path)
        try:
            input_stream = antlr4.InputStream(code)
            lexer = SolidityLexer(input_stream)
            lexer.removeErrorListeners()
            tokens = antlr4.CommonTokenStream(lexer)
            tokens.fill()
            combined['imports'][path] = _parse_import_tokens(tokens)
            parser = SolidityParser(tokens)
            parser.removeErrorListeners()
            antlr4.ParseTreeWalker().walk(lis, parser.sourceUnit())
        except Exception as exc:
            log.warning(f'scoped parse failed for {path}: {exc}')
            continue
        for cname, cdata in lis.contracts.items():
            # A contract name may be declared in several source units (e.g. two
            # library versions in one bundle). Keep every definition so binding
            # can fail closed instead of silently binding the surviving body.
            combined['contracts'].setdefault(cname, []).append(cdata)
        for key, members in lis.structs.items():
            # Same-name structs in different source units may have different
            # layouts. Keep distinct definitions so lookups can fail closed;
            # identical duplicates (flattened bundles) dedupe away.
            combined['structs'].setdefault(key, set()).add(tuple(members))
        combined['enums'] |= lis.enums
        combined['contract_names'] |= lis.contract_names
    return combined


# ── Source-side type canonicalization ─────────────────────────────────────────

def _split_array_suffix(t: str):
    m = _ARRAY_SUFFIX_RE.search(t)
    if m:
        return t[:m.start()].strip(), m.group(0)
    return t.strip(), ''


def _expand_struct(name: str, members, scope_contract, parsed, suffix, _seen) -> str:
    _seen = _seen or set()
    if name in _seen:
        raise UnresolvableType(f'recursive struct {name}')
    _seen = _seen | {name}
    inner = ','.join(_canonical_source_type(m, scope_contract, parsed, _seen) for m in members)
    return f'({inner}){suffix}'


def _canonical_source_type(type_text: str, scope_contract, parsed, _seen=None) -> str:
    t = type_text.replace(' payable', '').replace('payable', '').strip()
    for kw in ('memory', 'calldata', 'storage'):
        t = re.sub(rf'\b{kw}\b', '', t).strip()
    base, suffix = _split_array_suffix(t)
    elem = _canonical_elementary(base)
    if re.fullmatch(r'(u?int\d*|u?fixed\d*x\d*|bytes\d*|address|bool|string|byte)', elem):
        return f'{elem}{suffix}'
    if '.' in base:
        # Qualified name: resolve in the named namespace. The qualifier may be
        # an import alias (Lib.Base.S -> contract Base, struct S), so also try
        # the qualifier's simple name; any ambiguity fails closed.
        qualifier, simple = base.rsplit('.', 1)
        scopes = {qualifier, qualifier.split('.')[-1]}
        if any((sc, simple) in parsed['enums'] for sc in scopes):
            return f'uint8{suffix}'
        defs = set()
        for sc in scopes:
            defs |= parsed['structs'].get((sc, simple), set())
        if len(defs) == 1:
            return _expand_struct(simple, next(iter(defs)), qualifier, parsed, suffix, _seen)
        if len(defs) > 1:
            raise UnresolvableType(f'ambiguous qualified struct {base}')
        if simple in parsed['contract_names']:
            return f'address{suffix}'
        raise UnresolvableType(f'unresolved qualified type: {type_text!r}')
    name = base
    if (scope_contract, name) in parsed['enums'] or (None, name) in parsed['enums']:
        return f'uint8{suffix}'
    if name in parsed['contract_names']:
        return f'address{suffix}'
    defs = parsed['structs'].get((scope_contract, name), set()) | parsed['structs'].get((None, name), set())
    if len(defs) > 1:
        raise UnresolvableType(f'ambiguous struct {name}: {len(defs)} distinct declarations')
    if defs:
        return _expand_struct(name, next(iter(defs)), scope_contract, parsed, suffix, _seen)
    raise UnresolvableType(f'unknown type: {type_text!r}')


def _source_signature(entry: dict, parsed) -> str:
    types = [_canonical_source_type(t, entry['contract'], parsed) for t in entry['param_types']]
    return f"{entry['name']}({','.join(types)})"


# ── Binding ────────────────────────────────────────────────────────────────────

class AmbiguousContract(Exception):
    """A needed contract name has several declarations in the bundle."""


def _sole_def(contract: str, parsed) -> dict:
    defs = parsed['contracts'].get(contract, [])
    if len(defs) != 1:
        raise AmbiguousContract(f'{len(defs)} declarations of {contract}')
    return defs[0]


class UnsupportedAncestry(Exception):
    """A base-class reference cannot be proven to a unique contract identity;
    binding must fail closed."""


def _resolve_import_path(imp: str, from_path: str, parsed):
    """Resolve an import path to a key of parsed['sources_paths'].
    Returns the matching source-unit path or None when it is not in the
    bundle (never guesses by basename)."""
    candidates = [posixpath.normpath(posixpath.join(posixpath.dirname(from_path), imp)), imp]
    for cand in candidates:
        if cand in parsed['sources_paths']:
            return cand
    return None


def _resolve_base(base: str, from_path: str, parsed) -> str:
    """Resolve a raw (possibly qualified / import-aliased) base-class name to
    the globally unique contract name it refers to.

    Import/source identity rules:
      - `X as Y` symbol import: Y resolves ONLY to X in the imported file.
      - `* as Q` file import: Q.Name resolves ONLY to Name in that file.
      - Any other qualified name (Q.Name without a matching file alias) is
        unsupported and fails closed - qualifier stripping could bind an
        unrelated same-named contract.
      - A plain name resolves by global name, requiring exactly one
        declaration in the bundle (duplicates fail closed in _sole_def).
    """
    imports = parsed['imports'].get(from_path, {'symbols': {}, 'file_aliases': {}, 'plain': []})
    if '.' in base:
        qualifier, _, name = base.partition('.')
        imp = imports['file_aliases'].get(qualifier)
        if imp is None:
            raise UnsupportedAncestry(f'qualified base {base} without import identity')
        resolved_path = _resolve_import_path(imp, from_path, parsed)
        if resolved_path is None:
            raise UnsupportedAncestry(f'import {imp} not in bundle')
        defs = [d for d in parsed['contracts'].get(name, []) if d['path'] == resolved_path]
        if len(defs) != 1:
            raise UnsupportedAncestry(f'{len(defs)} declarations of {name} in {resolved_path}')
        return name
    sym = imports['symbols'].get(base)
    if sym is not None:
        imp, orig = sym
        resolved_path = _resolve_import_path(imp, from_path, parsed)
        if resolved_path is None:
            raise UnsupportedAncestry(f'import {imp} not in bundle')
        defs = [d for d in parsed['contracts'].get(orig, []) if d['path'] == resolved_path]
        if len(defs) != 1:
            raise UnsupportedAncestry(f'{len(defs)} declarations of {orig} in {resolved_path}')
        return orig
    return base


def _ancestors(contract: str, parsed) -> set:
    seen, stack = set(), [contract]
    while stack:
        cur = stack.pop()
        cur_def = _sole_def(cur, parsed)
        for raw_base in cur_def.get('bases', []):
            base = _resolve_base(raw_base, cur_def.get('path', ''), parsed)
            if base in parsed['contracts'] and base not in seen:
                _sole_def(base, parsed)  # ambiguous lineage fails closed
                seen.add(base)
                stack.append(base)
    return seen


def bind_function(bundle: dict, parsed: dict, selector: str, lines_by_path: dict):
    """Bind a 4-byte selector to exactly one executable body.

    bundle: {'contract_name', 'abi', 'proxy'} from the explorer response.
    parsed: output of parse_source_units.
    Returns {'status', 'bodies', 'reason'}; bodies items carry
    {path, start_line, end_line, content, contract, signature}.
    """
    if bundle.get('proxy'):
        return {'status': 'proxy_implementation', 'bodies': [],
                'reason': 'proxy contract: implementation at tx block is unresolved by design'}
    abi = bundle.get('abi')
    if not isinstance(abi, list) or not abi:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'abi_unavailable'}

    wanted = selector.strip().lower()
    matches = []
    for entry in abi:
        if not isinstance(entry, dict) or entry.get('type') != 'function':
            continue
        try:
            if function_selector(entry.get('name', ''), entry.get('inputs') or []) == wanted:
                matches.append(entry)
        except UnresolvableType as exc:
            log.warning(f'ABI canonicalization failed: {exc}')
            return {'status': 'unresolved', 'bodies': [], 'reason': f'abi_type_unresolvable: {exc}'}
    if not matches:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'selector_not_in_abi'}
    if len(matches) > 1:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'selector_collision_in_abi'}

    fn = matches[0]
    try:
        target_sig = canonical_signature(fn['name'], fn.get('inputs') or [])
    except UnresolvableType as exc:
        return {'status': 'unresolved', 'bodies': [], 'reason': f'abi_type_unresolvable: {exc}'}

    contract = bundle.get('contract_name')
    if not contract or contract not in parsed['contracts']:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'contract_not_in_source'}
    try:
        target_def = _sole_def(contract, parsed)
    except AmbiguousContract:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'duplicate_contract_declarations'}

    def matching_bodies(contract_name):
        """(matches, unresolvable) among executable bodies of fn['name'].
        An unresolvable same-name declaration shadows ancestors (Solidity name
        hiding), so it must force fail-closed, never a silent fallthrough."""
        out, unresolvable = [], False
        for entry in _sole_def(contract_name, parsed)['functions'].get(fn['name'], []):
            if not entry['has_body']:
                continue
            try:
                if _source_signature(entry, parsed) == target_sig:
                    out.append((contract_name, entry))
            except UnresolvableType:
                unresolvable = True
        return out, unresolvable

    try:
        direct, direct_unresolvable = matching_bodies(contract)
        target_declared = bool(_sole_def(contract, parsed)['functions'].get(fn['name']))
    except AmbiguousContract:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'duplicate_contract_declarations'}
    if len(direct) == 1 and not direct_unresolvable:
        kind, found = 'direct_verified', direct
    elif len(direct) > 1:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'multiple_bodies_in_contract'}
    elif direct_unresolvable:
        return {'status': 'unresolved', 'bodies': [], 'reason': 'unresolvable_direct_signature'}
    elif target_declared:
        # same-name declaration(s) exist but none has a provable matching body
        return {'status': 'unresolved', 'bodies': [], 'reason': 'no_executable_body'}
    else:
        try:
            found = []
            for anc in _ancestors(contract, parsed):
                matches, anc_unresolvable = matching_bodies(anc)
                if anc_unresolvable:
                    return {'status': 'unresolved', 'bodies': [], 'reason': 'unresolvable_inherited_signature'}
                found.extend(matches)
        except AmbiguousContract:
            return {'status': 'unresolved', 'bodies': [], 'reason': 'duplicate_contract_declarations'}
        except UnsupportedAncestry as exc:
            return {'status': 'unresolved', 'bodies': [], 'reason': f'unsupported_ancestry: {exc}'}
        if not found:
            return {'status': 'unresolved', 'bodies': [], 'reason': 'no_executable_body'}
        # effective implementation = unique most-derived candidate
        most_derived = []
        for cname, entry in found:
            others = {c for c, _ in found if c is not cname}
            if all(o in _ancestors(cname, parsed) for o in others):
                most_derived.append((cname, entry))
        if len(most_derived) != 1:
            return {'status': 'unresolved', 'bodies': [], 'reason': 'ambiguous_inherited_implementation'}
        kind = 'inherited_verified'

    bodies = []
    for cname, entry in found if kind == 'direct_verified' else most_derived:
        lines = lines_by_path.get(entry['path'], [])
        content = '\n'.join(lines[entry['start_line'] - 1:entry['end_line']])
        bodies.append({
            'path': entry['path'],
            'start_line': entry['start_line'],
            'end_line': entry['end_line'],
            'content': content,
            'contract': cname,
            'signature': target_sig,
        })
    return {'status': kind, 'bodies': bodies, 'reason': ''}
