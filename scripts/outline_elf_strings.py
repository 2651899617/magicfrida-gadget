#!/usr/bin/env python3
"""AST-only outliner for already preprocessed C/C++ translation units.

Integration API: outline_source(source, language='c', filename='<input>') returns
(output_bytes, report).  OutlineError carries a failure report.  This does not
rename APIs, rewrite binaries, invoke a compiler, or infer safety from branding.
The emitted code needs the translation unit's existing GLib declarations, and
GNU C/C++ constructor, typeof, and trap support.  No includes/macros are emitted.
"""

import argparse
from bisect import bisect_right
from collections import namedtuple
import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys

PARSER_PINS = {
    'tree-sitter': '0.25.2',
    'tree-sitter-c': '0.24.2',
    'tree-sitter-cpp': '0.23.4',
}
XOR_KEY = 0xa5
RESOURCE_NAME = re.compile(r'gumjs_[A-Za-z0-9_]+_(?:bytecode|source_code|source_map)\Z')
LITERAL_TYPES = {'string_literal', 'raw_string_literal', 'concatenated_string'}
SCOPE_TYPES = {'translation_unit', 'compound_statement', 'function_definition',
               'for_statement', 'namespace_definition'}


class OutlineError(ValueError):
    def __init__(self, message, report):
        super().__init__(message)
        self.report = report


class Unsupported(ValueError):
    pass


# These spellings are compiler keywords, not arbitrary identifiers/macros.  The
# shadow is only for the pinned parsers: no normalization is an output edit.
_KEYWORD_ALIASES = {b'__signed': b'signed', b'__signed__': b'signed'}
_NULLABILITY = {b'_Nullable', b'_Nonnull', b'_Null_unspecified', b'_Nullable_result'}
_TYPEOF = {b'typeof', b'__typeof', b'__typeof__'}
# Audit the attribute *envelope* and its arguments as well as its name.  Unknown
# attributes are left to the real grammar (and remain unsafe for slot/type use).
_GNU_ATTRIBUTES = frozenset('''
    alias aligned alloc_align alloc_size always_inline annotate artificial
    availability cleanup cold const constructor deprecated destructor diagnose_as_builtin
    diagnose_if enum_extensibility error externally_visible fallthrough flatten
    format format_arg gnu_inline hot leaf malloc may_alias minsize mode no_sanitize
    no_sanitize_address no_sanitize_thread no_sanitize_undefined no_stack_protector
    neon_polyvector_type neon_vector_type nodebug noinline nonnull noreturn nothrow
    optimize overloadable packed
    pass_dynamic_object_size pass_object_size pure returns_nonnull section sentinel
    swift_name target tls_model transparent_union type_visibility unavailable unused used
    vector_size visibility warn_unused_result warning weak weak_import weakref
'''.split())
_ATTRIBUTE_NODE_TYPES = {'attribute_specifier', 'attribute_declaration', 'ms_declspec_modifier'}
_Token = namedtuple('_Token', 'kind start end value')
_TOKEN_RE = re.compile(rb'''(?P<space>\s+)|(?P<comment>/\*[\s\S]*?\*/|//(?:\\\r?\n|[^\r\n])*)
    |(?P<raw>(?:u8|[uUL])?R")
    |(?P<string>(?:u8|[uUL])?"(?:\\[\s\S]|[^"\\\r\n])*")
    |(?P<char>(?:u8|[uUL])?'(?:\\[\s\S]|[^'\\\r\n])*')
    |(?P<identifier>[A-Za-z_$\x80-\xff][A-Za-z_0-9$\x80-\xff]*)
    |(?P<number>[0-9][A-Za-z_0-9.']*)|(?P<punct>[\s\S])''', re.X)


def _lex(source, include_directives=False):
    """Significant preprocessing tokens; never scan keywords inside literals."""
    tokens = []
    i = 0
    directive_prefix = True
    while i < len(source):
        match = _TOKEN_RE.match(source, i)
        kind, end = match.lastgroup, match.end()
        if kind == 'raw':
            opening = source.find(b'(', end, end + 17)
            delimiter = source[end:opening] if opening != -1 else b''
            if (opening == -1 or any(c in b' ()\\\t\r\n\v\f' for c in delimiter)):
                kind, end = 'invalid', len(source)
            else:
                closing = source.find(b')' + delimiter + b'"', opening + 1)
                kind, end = ('invalid', len(source)) if closing == -1 else ('string', closing + len(delimiter) + 2)
        elif kind == 'punct' and source[i:i + 1] == b'#' and directive_prefix:
            # Leave real directives intact for validate_input(), including a
            # line-leading comment/whitespace prefix.  A # inside a comment,
            # ordinary literal or multiline raw literal is never a directive.
            end = source.find(b'\n', end)
            end = len(source) if end == -1 else end + 1
            while source[i:end].rstrip(b'\r\n').endswith(b'\\') and end < len(source):
                following = source.find(b'\n', end)
                end = len(source) if following == -1 else following + 1
            kind = 'directive'
        elif kind == 'punct' and source[i:i + 1] in {b'"', b"'"}:
            kind = 'invalid'
        if kind in {'space', 'comment'}:
            if b'\n' in source[i:end]:
                directive_prefix = True
        elif kind == 'directive':
            directive_prefix = True
        else:
            directive_prefix = False
        if kind not in {'space', 'comment', 'directive'} or (include_directives and kind == 'directive'):
            tokens.append(_Token(kind, i, end, source[i:end]))
        i = end
    return tokens


def _balanced_tokens(tokens):
    pairs, stack = {}, []
    closing = {b')': b'(', b']': b'[', b'}': b'{'}
    for i, token in enumerate(tokens):
        if token.kind != 'punct':
            continue
        if token.value in {b'(', b'[', b'{'}:
            stack.append(i)
        elif token.value in closing:
            if stack and tokens[stack[-1]].value == closing[token.value]:
                start = stack.pop()
                pairs[start] = i
            else:
                stack.clear()
    return pairs


def _padded(original, replacement=b''):
    """Keep byte count and every CR/LF, including multiline extension operands."""
    result = bytearray(c if c in (10, 13) else 32 for c in original)
    if replacement:
        if len(replacement) > len(result) or any(c in (10, 13) for c in original[:len(replacement)]):
            raise Unsupported('parser_shadow_token_does_not_fit')
        result[:len(replacement)] = replacement
    return bytes(result)


_LINE_MARKER = re.compile(rb'(?m)^[ \t]*#[ \t]*(?:line[ \t]+)?([0-9]+)[ \t]+("(?:\\[^\r\n]|[^"\\\r\n])*")((?:[ \t]+[0-9]+)*)[ \t]*(?:\r?\n|$)')
_SYNTHETIC_ORIGIN = b'#line 1 "<nianchu-outline-generated>"\n'
# Labels must be identifier tokens for both GNU C and Clang C/C++.  Reserved
# compiler spellings (__foo / _Foo) and either language's keywords can otherwise
# be ignored by Clang while GCC still performs the modeled stack operation.
_PACK_LABEL_KEYWORDS = frozenset(rb'''
    alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept
    auto bitand bitor bool break case catch char char8_t char16_t char32_t class
    compl concept const consteval constexpr constinit const_cast continue
    co_await co_return co_yield decltype default delete do double dynamic_cast
    else enum explicit export extern false final float for friend goto if import
    inline int long module mutable namespace new noexcept not not_eq nullptr
    operator or or_eq override private protected public reflexpr register
    reinterpret_cast requires restrict return short signed sizeof static
    static_assert static_cast struct switch synchronized template this
    thread_local throw transactional_safe transactional_safe_dynamic true try
    typedef typeid typename typeof typeof_unqual union unsigned using virtual
    void volatile wchar_t while xor xor_eq push pop
'''.split())


def _packing_directive(raw):
    """Recognize literal GNU/Clang pack forms without rewriting their bytes."""
    match = re.fullmatch(rb'\s*#\s*pragma\s+pack\s*\(([^()\r\n]*)\)\s*', raw)
    if match is None:
        return None
    body = match.group(1).strip()
    parts = [part.strip() for part in body.split(b',')] if body else []
    alignments = {b'1', b'2', b'4', b'8', b'16'}
    if not parts:
        return {'action': 'reset', 'label': None, 'alignment': None}
    if len(parts) == 1 and parts[0] in alignments:
        return {'action': 'set', 'label': None, 'alignment': int(parts[0])}
    if parts[0] not in {b'push', b'pop'} or len(parts) > 3:
        return None
    label, alignment = None, None
    if len(parts) >= 2:
        if parts[1] in alignments:
            if len(parts) != 2:
                return None
            alignment = int(parts[1])
        elif (re.fullmatch(rb'[A-Za-z_][A-Za-z_0-9]*', parts[1])
                and parts[1] not in _PACK_LABEL_KEYWORDS
                and not re.match(rb'(?:__|_[A-Z])', parts[1])):
            label = parts[1].decode('ascii')
            if len(parts) == 3:
                if parts[2] not in alignments:
                    return None
                alignment = int(parts[2])
        else:
            return None
    # GCC ignores pop with an alignment, while Clang applies it (and warns
    # for pop,label,alignment).  Never model a compiler-dependent stack change.
    if parts[0] == b'pop' and alignment is not None:
        return None
    return {'action': parts[0].decode('ascii'), 'label': label, 'alignment': alignment}


def _origin_path(raw):
    try:
        name = _decode_ordinary(raw).decode('utf-8')
    except (Unsupported, UnicodeError):
        return None
    if name.startswith('<') and name.endswith('>'):
        return None
    path = Path(name)
    if not path.is_absolute():
        return None
    return os.path.normcase(str(path.resolve())).replace('\\', '/')


def _brace_kind(tokens):
    """Classify only the lexical shells needed at an origin boundary.

    Parenthesis operands stay in the token list, but a function parameter list
    must follow a declarator name rather than an attribute/type operator.
    Aggregate definitions still require their trailing declaration semicolon.
    """
    pairs = _balanced_tokens(tokens)
    top = []
    function_parameters = False
    i = 0
    nonfunctions = {
        b'__attribute__', b'__attribute', b'__declspec', b'alignas',
        b'_Alignas', b'noexcept', b'decltype', b'typeof', b'__typeof',
        b'__typeof__', b'__underlying_type', b'requires', b'if', b'while',
        b'switch', b'for', b'catch', b'sizeof', b'alignof', b'void',
        b'char', b'int', b'long', b'short', b'float', b'double', b'bool'}
    while i < len(tokens):
        token = tokens[i]
        top.append(token)
        if token.value in {b'(', b'['} and i in pairs:
            if (token.value == b'(' and i > 0
                    and tokens[i - 1].kind == 'identifier'
                    and tokens[i - 1].value not in nonfunctions):
                function_parameters = True
            i = pairs[i] + 1
        else:
            i += 1
    values = [token.value for token in top]
    if b'namespace' in values and b'=' not in values:
        return 'namespace'
    if (b'extern' in values and any(token.kind == 'string'
            and token.value in {b'"C"', b'"C++"'} for token in top)
            and not function_parameters):
        return 'linkage'
    if function_parameters and b'=' not in values:
        return 'function'
    if any(value in {b'struct', b'class', b'union', b'enum'} for value in values):
        return 'aggregate'
    return 'other'


class _HeaderOrigins:
    """An explicit, C++-only parser boundary, never an emitter passthrough.

    Only a complete balanced run of tokens from the selected physical header
    roots is hidden.  A delimiter crossing any owned/header boundary is fatal,
    even if a later compiler would accept it.  C/GLib/owned headers stay parsed.
    """
    def __init__(self, source, roots):
        self.source = source
        self.roots = []
        self.ranges = []
        self.blocks = []
        self.symbols = set()
        self.markers = []
        for root in roots:
            path = Path(root)
            if not path.is_absolute() or not path.is_dir():
                raise Unsupported('cpp_opaque_root_not_physical_directory')
            value = os.path.normcase(str(path.resolve())).replace('\\', '/').rstrip('/')
            # Do not accept an input itself, a drive, or all of usr/include as
            # a convenient boundary.  The caller must name an external subtree.
            if len(value.split('/')) < 4:
                raise Unsupported('cpp_opaque_root_too_broad')
            if value not in self.roots:
                self.roots.append(value)
        if not self.roots:
            self.view = source
            return
        lexical = _lex(source, include_directives=True)
        self.markers = [token for token in lexical
                        if token.kind == 'directive' and _LINE_MARKER.fullmatch(token.value)]
        if not self.markers:
            raise Unsupported('cpp_opaque_requires_line_markers')
        origin = None
        cursor = 0
        for marker in self.markers:
            self.add_block(cursor, marker.start, origin)
            origin = _origin_path(_LINE_MARKER.fullmatch(marker.value).group(2))
            cursor = marker.end
        self.add_block(cursor, len(source), origin)
        shadow = bytearray(source)
        opening = {b'(': b')', b'[': b']', b'{': b'}'}
        closing = {v: k for k, v in opening.items()}
        stack = []
        frames = []
        pending = []
        opaque_base = None
        run_start = None
        run_end = None
        run_origins = set()
        last_mode = None
        for block in self.blocks:
            tokens = _lex(source[block['start']:block['end']])
            if not tokens:
                continue
            mode = block['opaque']
            transition = last_mode is not None and mode != last_mode
            if transition:
                if last_mode and tuple(stack) != opaque_base:
                    raise Unsupported('cpp_opaque_cross_origin_delimiter')
                if pending:
                    raise Unsupported('cpp_opaque_cross_origin_declaration')
                if last_mode:
                    self.ranges.append({'start': run_start, 'end': run_end,
                                        'origins': sorted(run_origins), 'kind': 'header-origin', 'names': ()})
                    run_start, run_end, run_origins = None, None, set()
                    opaque_base = None
            if mode:
                if run_start is None:
                    if pending:
                        raise Unsupported('cpp_opaque_cross_origin_declaration')
                    if any(frame['kind'] not in {'namespace', 'linkage'} for frame in frames):
                        raise Unsupported('cpp_opaque_unsupported_owned_scope')
                    opaque_base = tuple(stack)
                    run_start = block['start']
                run_end = block['end']
                run_origins.add(block['origin'])
                # Hide the whole external body, then restore only directives
                # emitted by the lexical pass.  Line-shaped text in comments
                # and raw strings must never change parser or packing state.
                start, end = block['start'], block['end']
                shadow[start:end] = _padded(source[start:end])
                for directive in _lex(source[start:end], include_directives=True):
                    if directive.kind == 'directive':
                        begin, finish = start + directive.start, start + directive.end
                        shadow[begin:finish] = source[begin:finish]
                self.symbols.update(t.value for t in tokens if t.kind == 'identifier')
            for token in tokens:
                if token.kind == 'punct' and token.value in opening:
                    if token.value == b'{':
                        kind = _brace_kind(pending)
                        frames.append({'kind': kind, 'prefix': pending, 'opening': token})
                        pending = []
                    else:
                        frames.append({'kind': 'operand', 'prefix': pending, 'opening': token})
                        pending = []
                    stack.append(token.value)
                elif token.kind == 'punct' and token.value in closing:
                    if mode and len(stack) <= len(opaque_base):
                        raise Unsupported('cpp_opaque_cross_origin_delimiter')
                    if not stack or stack.pop() != closing[token.value]:
                        raise Unsupported('cpp_opaque_unbalanced_delimiter')
                    frame = frames.pop()
                    if token.value == b'}' and frame['kind'] in {'namespace', 'linkage', 'function'}:
                        pending = []
                    elif frame['kind'] == 'operand':
                        pending = frame['prefix'] + [frame['opening']] + pending + [token]
                    else:
                        pending = frame['prefix'] + [token]
                elif token.kind == 'punct' and token.value == b';':
                    pending = []
                else:
                    pending.append(token)
            last_mode = mode
        if last_mode:
            if tuple(stack) != opaque_base:
                raise Unsupported('cpp_opaque_unbalanced_delimiter')
            if pending:
                raise Unsupported('cpp_opaque_cross_origin_declaration')
            self.ranges.append({'start': run_start, 'end': run_end,
                                'origins': sorted(run_origins), 'kind': 'header-origin', 'names': ()})
        self.view = bytes(shadow)

    def add_block(self, start, end, origin):
        if start >= end:
            return
        opaque = origin is not None and any(origin == root or origin.startswith(root + '/') for root in self.roots)
        self.blocks.append({'start': start, 'end': end, 'origin': origin, 'opaque': opaque})

    def summary(self):
        return {'roots': self.roots, 'balanced_regions': len(self.ranges),
                'opaque_bytes': sum(b['end'] - b['start'] for b in self.blocks if b['opaque']),
                'original_bytes_emitted': True}


class _ParserShadow:
    """Audited, offset-identical parser input plus all hidden safety contexts.

    GNU typeof's operand is separately parsed as sizeof(type-or-expression),
    then represented by an *unknown* type, never inferred to be int in safety
    analysis.  Attribute arguments are separately parsed in a supported grammar
    position.  An invalid/unrecognized extension cannot hide arbitrary errors.
    """
    def __init__(self, source, language, parser, cpp_opaque_roots=()):
        self.source, self.language, self.parser = source, language, parser
        self.origins = _HeaderOrigins(source, cpp_opaque_roots)
        self.tokens = _lex(self.origins.view)
        self.pairs = _balanced_tokens(self.tokens)
        self.regions = list(self.origins.ranges)
        shadow = bytearray(self.origins.view)
        # The pinned grammar misinterprets legal #line between enumerators as
        # a missing comma.  Audited line directives are parser trivia only;
        # their original bytes and physical origin remain in compiler output.
        if cpp_opaque_roots:
            for marker in self.origins.markers:
                self.replace(shadow, marker.start, marker.end, 'line-marker')
        typeops = []
        for i, token in enumerate(self.tokens):
            if token.kind != 'identifier':
                continue
            if token.value in _KEYWORD_ALIASES:
                self.replace(shadow, token.start, token.end, 'keyword-alias', _KEYWORD_ALIASES[token.value])
            elif token.value in _NULLABILITY:
                self.replace(shadow, token.start, token.end, 'nullability')
            elif token.value in {b'__attribute__', b'__attribute'}:
                parsed = self.attribute(i)
                if parsed is not None:
                    end, names = parsed
                    raw = source[token.start:self.tokens[end].end]
                    probe = b'int ' + raw + b' _nso_attribute_probe;\n'
                    if not parser.parse(probe).root_node.has_error:
                        self.replace(shadow, token.start, self.tokens[end].end, 'attribute', names=names)
            elif token.value in _TYPEOF and i + 1 < len(self.tokens) and self.tokens[i + 1].value == b'(':
                end = self.pairs.get(i + 1)
                if end is not None and end > i + 2:
                    typeops.append((i, end))
            elif language == 'cpp' and token.value == b'__underlying_type' and i + 1 < len(self.tokens) and self.tokens[i + 1].value == b'(':
                end = self.pairs.get(i + 1)
                if end is not None and end > i + 2:
                    typeops.append((i, end))
        # Inner operands first, so a nested GNU typeof is itself syntax-checked.
        probes = {}
        for i, end in sorted(typeops, key=lambda pair: self.tokens[pair[1]].end - self.tokens[pair[0]].start):
            token = self.tokens[i]
            operand = bytes(shadow[self.tokens[i + 1].start:self.tokens[end].end])
            if operand not in probes:
                probe = b'void _nso_type_probe(void) { (void) sizeof ' + operand + b'; }\n'
                probes[operand] = not parser.parse(probe).root_node.has_error
            if probes[operand]:
                self.replace(shadow, token.start, self.tokens[end].end, 'typeof', b'int')
        # GNU builtins have explicit type operands, which these grammars treat
        # as expression arguments.  Validate only those operands as types; keep
        # every value argument, comma and call boundary in the shadow AST.
        for i, token in enumerate(self.tokens):
            type_indices = {b'__builtin_va_arg': {1}, b'__builtin_types_compatible_p': {0, 1},
                            b'__builtin_offsetof': {0}}.get(token.value) if token.kind == 'identifier' else None
            if type_indices is None or i + 1 >= len(self.tokens) or self.tokens[i + 1].value != b'(':
                continue
            end = self.pairs.get(i + 1)
            if end is None:
                continue
            arguments, start, cursor = [], i + 2, i + 2
            while cursor < end:
                if self.tokens[cursor].value == b',':
                    arguments.append((start, cursor))
                    start = cursor + 1
                cursor = self.pairs.get(cursor, cursor) + 1
            arguments.append((start, end))
            if len(arguments) != 2 or any(begin == finish for begin, finish in arguments):
                continue
            for index in type_indices:
                begin, finish = arguments[index]
                start, stop = self.tokens[begin].start, self.tokens[finish - 1].end
                operand = bytes(shadow[start:stop])
                probe = b'void _nso_builtin_type_probe(void) { (void) sizeof(' + operand + b'); }\n'
                if not parser.parse(probe).root_node.has_error:
                    self.replace(shadow, start, stop, 'builtin-type', b'0')
        self.view = bytes(shadow)
        if language == 'cpp':
            self.cpp_declarators(shadow)
            self.view = bytes(shadow)
        elif language == 'c':
            self.c_anonymous_bitfields(shadow)
            self.view = bytes(shadow)
        preliminary = parser.parse(self.view)
        # Only declarator labels, confirmed by an AST declaration context.  A
        # basic/extended asm *statement* must retain its instruction operands.
        for node in _walk(preliminary.root_node):
            if node.type != 'gnu_asm_expression':
                continue
            if not any(p.type in {'declaration', 'type_definition', 'field_declaration'} for p in _parents(node)):
                continue
            start = next((i for i, t in enumerate(self.tokens) if t.start == node.start_byte), None)
            if start is None or self.tokens[start].value not in {b'asm', b'__asm', b'__asm__'}:
                continue
            opening = start + 1
            end = self.pairs.get(opening)
            if (opening >= len(self.tokens) or self.tokens[opening].value != b'(' or end is None
                    or end <= opening + 1 or any(t.kind != 'string' for t in self.tokens[opening + 1:end])):
                continue
            self.replace(shadow, node.start_byte, self.tokens[end].end, 'asm-declarator')
        self.view = bytes(shadow)
        self.tree = parser.parse(self.view)
        self.attachments = {}
        self.type_contexts = {}
        self.bind_regions()
        self.bind_cpp_regions()
        self.bind_c_bitfields()
        self.starts = [t.start for t in self.tokens]

    @staticmethod
    def bitfield_signature(node, offset=0):
        return (str(node), tuple((n.type, n.start_byte - offset, n.end_byte - offset,
                                 n.is_named, n.is_missing) for n in _walk_all(node)))

    def c_anonymous_bitfields(self, shadow):
        # The pinned C grammar requires a name on otherwise legal anonymous
        # bitfields.  Validate the entire original field with an inserted probe
        # name, then project only its original type span to T x.  Neither the
        # width expression nor its compile-time/resource uses can disappear.
        tree = self.parser.parse(bytes(shadow))
        integer_words = {b'char', b'signed', b'unsigned', b'short', b'int', b'long',
                         b'_Bool', b'__int128'}
        excluded = _PACK_LABEL_KEYWORDS | set(_KEYWORD_ALIASES) | _NULLABILITY | _TYPEOF | {
            b'__underlying_type', b'__func__', b'__FUNCTION__', b'__PRETTY_FUNCTION__'}
        prefix, suffix = b'struct _nso_bitfield_owner { ', b' };\n'
        insertion = b' _nso_bitfield_probe '
        for field in _walk(tree.root_node):
            if field.type != 'field_declaration' or field.parent is None or field.parent.type != 'field_declaration_list':
                continue
            base = field.child_by_field_name('type')
            declarators = field.children_by_field_name('declarator')
            clauses = [n for n in field.named_children if n.type == 'bitfield_clause']
            errors = [n for n in _walk_all(field) if n.type == 'ERROR' or n.is_missing]
            if (len(declarators) != 1 or declarators[0].type != 'field_identifier'
                    or not declarators[0].is_missing or errors != [declarators[0]]
                    or base is None or base.has_error
                    or base.type not in {'primitive_type', 'sized_type_specifier', 'type_identifier'}
                    or len(clauses) != 1 or clauses[0].has_error):
                continue
            name, clause = declarators[0], clauses[0]
            widths = [n for n in clause.named_children if n.type != 'comment']
            colons = [n for n in clause.children if n.type == ':']
            semicolons = [n for n in field.children if n.type == ';']
            if (len(widths) != 1 or widths[0].has_error or len(colons) != 1
                    or len(semicolons) != 1 or semicolons[0].is_missing
                    or semicolons[0].end_byte != field.end_byte
                    or not (base.end_byte <= name.start_byte == name.end_byte <= colons[0].start_byte)
                    or _lex(bytes(shadow[base.end_byte:colons[0].start_byte]))):
                continue
            width, colon, semicolon = widths[0], colons[0], semicolons[0]
            raw_type = self.source[base.start_byte:base.end_byte]
            type_tokens = _lex(raw_type)
            if base.type == 'type_identifier':
                valid_type = (len(type_tokens) == 1 and type_tokens[0].kind == 'identifier'
                              and type_tokens[0].value not in excluded)
            else:
                valid_type = bool(type_tokens) and all(t.kind == 'identifier' and t.value in integer_words for t in type_tokens)
            if (not valid_type or len(raw_type) < 3 or any(c in (10, 13) for c in raw_type[:3])
                    or self.source[width.start_byte:width.end_byte] != bytes(shadow[width.start_byte:width.end_byte])):
                continue
            raw_field = self.source[field.start_byte:field.end_byte]
            at = colon.start_byte - field.start_byte
            named_source = prefix + raw_field[:at] + insertion + raw_field[at:] + suffix
            named_tree = self.parser.parse(named_source)
            named_fields = [n for n in _walk(named_tree.root_node) if n.type == 'field_declaration']
            if named_tree.root_node.has_error or len(named_fields) != 1:
                continue
            named_field = named_fields[0]
            named_base = named_field.child_by_field_name('type')
            named_names = named_field.children_by_field_name('declarator')
            named_clauses = [n for n in named_field.named_children if n.type == 'bitfield_clause']
            delta = len(prefix) - field.start_byte
            width_delta = delta + len(insertion)
            if (named_base is None or named_base.type != base.type
                    or (named_base.start_byte, named_base.end_byte) != (base.start_byte + delta, base.end_byte + delta)
                    or named_source[named_base.start_byte:named_base.end_byte] != raw_type
                    or len(named_names) != 1 or named_names[0].type != 'field_identifier'
                    or named_source[named_names[0].start_byte:named_names[0].end_byte] != b'_nso_bitfield_probe'
                    or (named_field.start_byte, named_field.end_byte) != (field.start_byte + delta, field.end_byte + width_delta)
                    or len(named_clauses) != 1
                    or (named_clauses[0].start_byte, named_clauses[0].end_byte) != (clause.start_byte + width_delta, clause.end_byte + width_delta)):
                continue
            named_widths = [n for n in named_clauses[0].named_children if n.type != 'comment']
            signature = self.bitfield_signature(width)
            if len(named_widths) != 1 or self.bitfield_signature(named_widths[0], width_delta) != signature:
                continue
            replacement = _padded(raw_type, b'T x')
            projected_source = (prefix + bytes(shadow[field.start_byte:base.start_byte]) + replacement
                                + bytes(shadow[base.end_byte:field.end_byte]) + suffix)
            projected_tree = self.parser.parse(projected_source)
            projected_fields = [n for n in _walk(projected_tree.root_node) if n.type == 'field_declaration']
            if projected_tree.root_node.has_error or len(projected_fields) != 1:
                continue
            projected_field = projected_fields[0]
            projected_base = projected_field.child_by_field_name('type')
            projected_names = projected_field.children_by_field_name('declarator')
            projected_clauses = [n for n in projected_field.named_children if n.type == 'bitfield_clause']
            if (projected_base is None or projected_base.type != 'type_identifier'
                    or (projected_base.start_byte, projected_base.end_byte) != (base.start_byte + delta, base.start_byte + delta + 1)
                    or len(projected_names) != 1 or projected_names[0].type != 'field_identifier'
                    or (projected_names[0].start_byte, projected_names[0].end_byte) != (base.start_byte + delta + 2, base.start_byte + delta + 3)
                    or (projected_field.start_byte, projected_field.end_byte) != (field.start_byte + delta, field.end_byte + delta)
                    or len(projected_clauses) != 1
                    or (projected_clauses[0].start_byte, projected_clauses[0].end_byte) != (clause.start_byte + delta, clause.end_byte + delta)):
                continue
            projected_widths = [n for n in projected_clauses[0].named_children if n.type != 'comment']
            if len(projected_widths) != 1 or self.bitfield_signature(projected_widths[0], delta) != signature:
                continue
            self.replace(shadow, base.start_byte, base.end_byte, 'anonymous-bitfield-type', b'T x')
            self.regions[-1].update(field_start=field.start_byte, field_end=field.end_byte,
                                    clause_start=clause.start_byte, clause_end=clause.end_byte,
                                    colon_start=colon.start_byte, colon_end=colon.end_byte,
                                    width_start=width.start_byte, width_end=width.end_byte,
                                    width_signature=signature,
                                    semicolon_start=semicolon.start_byte, semicolon_end=semicolon.end_byte)

    def bind_c_bitfields(self):
        if self.language != 'c':
            return
        for region in self.regions:
            if region['kind'] != 'anonymous-bitfield-type':
                continue
            node = self.tree.root_node.descendant_for_byte_range(region['field_start'], region['field_end'])
            owner = next((n for n in (node, *_parents(node)) if n.type == 'field_declaration'
                          and (n.start_byte, n.end_byte) == (region['field_start'], region['field_end'])), None)
            base = owner.child_by_field_name('type') if owner is not None else None
            names = owner.children_by_field_name('declarator') if owner is not None else []
            clauses = [n for n in owner.named_children if n.type == 'bitfield_clause'] if owner is not None else []
            semicolons = [n for n in owner.children if n.type == ';'] if owner is not None else []
            if (owner is None or owner.has_error or base is None or base.type != 'type_identifier'
                    or (base.start_byte, base.end_byte) != (region['start'], region['start'] + 1)
                    or self.view[base.start_byte:base.end_byte] != b'T'
                    or len(names) != 1 or names[0].type != 'field_identifier'
                    or (names[0].start_byte, names[0].end_byte) != (region['start'] + 2, region['start'] + 3)
                    or self.view[names[0].start_byte:names[0].end_byte] != b'x'
                    or len(clauses) != 1
                    or (clauses[0].start_byte, clauses[0].end_byte) != (region['clause_start'], region['clause_end'])
                    or len(semicolons) != 1
                    or (semicolons[0].start_byte, semicolons[0].end_byte) != (region['semicolon_start'], region['semicolon_end'])):
                raise Unsupported('c_anonymous_bitfield_context')
            widths = [n for n in clauses[0].named_children if n.type != 'comment']
            colons = [n for n in clauses[0].children if n.type == ':']
            if (len(widths) != 1 or (widths[0].start_byte, widths[0].end_byte) != (region['width_start'], region['width_end'])
                    or self.bitfield_signature(widths[0]) != region['width_signature']
                    or len(colons) != 1 or (colons[0].start_byte, colons[0].end_byte) != (region['colon_start'], region['colon_end'])):
                raise Unsupported('c_anonymous_bitfield_context')
            # Synthetic parser identifiers are never real fields or types.
            self.attachments.setdefault(owner.id, []).append(region)
            self.attachments.setdefault(base.id, []).append(region)

    def cpp_declarators(self, shadow):
        tokens = self.tokens
        tree = self.parser.parse(bytes(shadow))
        starts = {t.start: i for i, t in enumerate(tokens)}
        for node in _walk(tree.root_node):
            if node.type != 'init_declarator':
                continue
            value = node.child_by_field_name('value')
            declarator = node.child_by_field_name('declarator')
            function = next((n for n in _walk(declarator) if n.type == 'function_declarator'), None) if declarator is not None else None
            function_name = function.child_by_field_name('declarator') if function is not None else None
            if (value is None or function is None or value.type != 'delete_expression'
                    or (function_name is not None and any(n.type == 'pointer_declarator' for n in _walk(function_name)))):
                continue
            index = starts.get(value.start_byte)
            if (index is None or index == 0 or index + 1 >= len(tokens)
                    or tokens[index].value != b'delete' or tokens[index - 1].value != b'='
                    or tokens[index + 1].value != b';'):
                continue
            self.replace(shadow, tokens[index - 1].start, tokens[index].end, 'deleted-function')
        # The grammar does not accept abstract pointer-to-member declarators
        # in template type arguments.  Project only a lexically complete C::
        # scope before *, retaining the pointer, parameters, cv/ref/noexcept,
        # and every surrounding type token.  Mark the full type unknown later.
        tree = self.parser.parse(bytes(shadow))
        regions = []
        template_ranges = []
        for opening, token in enumerate(tokens):
            if token.value != b'<' or opening == 0 or tokens[opening - 1].kind != 'identifier':
                continue
            if opening < 2 or tokens[opening - 2].value not in {b'struct', b'class', b'union'}:
                continue
            depth, cursor = 1, opening + 1
            while cursor < len(tokens) and depth:
                if tokens[cursor].value in {b'(', b'[', b'{'}:
                    closing = self.pairs.get(cursor)
                    if closing is None:
                        break
                    cursor = closing + 1
                    continue
                if tokens[cursor].value == b'<':
                    depth += 1
                elif tokens[cursor].value == b'>':
                    depth -= 1
                elif tokens[cursor].value == b';':
                    break
                cursor += 1
            if depth == 0:
                template_ranges.append((tokens[opening].start, tokens[cursor - 1].end))
        for i in range(3, len(tokens)):
            if tokens[i].value != b'*' or [t.value for t in tokens[i - 2:i]] != [b':', b':']:
                continue
            name = i - 3
            if tokens[name].kind != 'identifier':
                continue
            begin = name
            while begin >= 3 and [t.value for t in tokens[begin - 2:begin]] == [b':', b':'] and tokens[begin - 3].kind == 'identifier':
                begin -= 3
            start, end = tokens[begin].start, tokens[i - 1].end
            # Do not turn the value expression &C::member / C::*anything into
            # a type.  A surrounding recognized type context is required.
            node = tree.root_node.descendant_for_byte_range(tokens[i].start, tokens[i].end)
            owner = next((n for n in (node, *_parents(node))
                          if n.type in {'template_argument_list', 'type_descriptor', 'type_definition',
                                        'alias_declaration', 'parameter_declaration', 'field_declaration',
                                        'declaration'}), None)
            anchored = next(((a, b) for a, b in template_ranges if a < start and tokens[i].end < b), None)
            if anchored is not None:
                owner_start, owner_end = anchored
                projected = bytes(shadow[owner_start:owner_end])
                relative = start - owner_start
                projected = projected[:relative] + _padded(self.source[start:end]) + projected[relative + end - start:]
                prefix = b'using _nso_member_probe = _nso_template'
                if self.member_type_probe(prefix + projected + b';\n', len(prefix) + tokens[i].start - owner_start, True):
                    regions.append((start, end))
                continue
            if owner is None:
                continue
            projected = bytes(shadow[owner.start_byte:owner.end_byte])
            relative = start - owner.start_byte
            if relative < 0:
                continue
            projected = projected[:relative] + _padded(self.source[start:end]) + projected[relative + end - start:]
            prefix, require_type = b'', False
            if owner.type == 'template_argument_list':
                prefix = b'using _nso_member_probe = _nso_template'
                probe, require_type = prefix + projected + b';\n', True
            elif owner.type == 'type_descriptor':
                prefix = b'using _nso_member_probe = '
                probe, require_type = prefix + projected + b';\n', True
            else:
                probe = projected if projected.rstrip().endswith(b';') else projected + b';'
                # Member/parameter fragments can be validated as a field or
                # function parameter without discarding any of their syntax.
                if owner.type == 'parameter_declaration':
                    prefix = b'void _nso_member_probe('
                    probe = prefix + projected + b');\n'
                elif owner.type == 'field_declaration':
                    prefix = b'struct _nso_member_probe { '
                    probe = prefix + probe + b' };\n'
            if self.member_type_probe(probe, len(prefix) + tokens[i].start - owner.start_byte, require_type):
                regions.append((start, end))
        for start, end in regions:
            self.replace(shadow, start, end, 'member-pointer')
        # This grammar accepts operator declarations but not explicit member
        # calls such as receiver.operator&().  Change just that operator-id to a
        # same-length identifier; receiver and every value argument stay parsed.
        tree = self.parser.parse(bytes(shadow))
        for node in _walk(tree.root_node):
            if node.type != 'operator_name' or node.parent is None or node.parent.type != 'ERROR':
                continue
            index = starts.get(node.start_byte)
            if index is None or index == 0:
                continue
            before = tokens[index - 1].value
            if before != b'.' and not (before == b'>' and index >= 2 and tokens[index - 2].value == b'-'):
                continue
            end = index + 1
            while end < len(tokens) and tokens[end].end <= node.end_byte:
                end += 1
            if end >= len(tokens) or tokens[end].value != b'(' or end not in self.pairs:
                continue
            raw = self.source[node.start_byte:node.end_byte]
            if not re.fullmatch(rb'operator\s*(?:\[\s*\]|\(\s*\)|->\*?|<<=?|>>=?|[+*/%^&|=!<>-]=?|\+\+|--|&&|\|\||~|(?:new|delete)\s*(?:\[\s*\])?)', raw):
                continue
            probe = b'void _nso_operator_probe(){ receiver.' + raw + b'(); }\n'
            projected = probe.replace(raw, b'_nso_op')
            if not self.parser.parse(projected).root_node.has_error:
                self.replace(shadow, node.start_byte, node.end_byte, 'operator-id', b'_nso_op')

        # Implicit operator calls in an unambiguous expression context can
        # also be mistaken for declarations (g(operator*())).  Normalize only
        # the operator-id, never its arguments or an actual operator signature.
        tree = self.parser.parse(bytes(shadow))
        for i, token in enumerate(tokens):
            if token.value != b'operator' or i == 0:
                continue
            cursor, ending = i + 1, None
            if cursor < len(tokens) and tokens[cursor].value in {b'(', b'['}:
                close = self.pairs.get(cursor)
                if close == cursor + 1:
                    ending = close + 1
            else:
                while cursor < len(tokens) and tokens[cursor].value not in {b'(', b';', b'{', b'}', b','}:
                    cursor += 1
                ending = cursor
            if ending is None or ending >= len(tokens) or tokens[ending].value != b'(' or ending not in self.pairs:
                continue
            raw = self.source[token.start:tokens[ending - 1].end]
            if not re.fullmatch(rb'operator\s*(?:\[\s*\]|\(\s*\)|->\*?|<<=?|>>=?|[+*/%^&|=!<>-]=?|\+\+|--|&&|\|\||~|(?:new|delete)\s*(?:\[\s*\])?)', raw):
                continue
            node = tree.root_node.descendant_for_byte_range(token.start, token.end)
            if not any(n.type in {'function_definition', 'lambda_expression'} for n in (node, *_parents(node))):
                continue
            previous = tokens[i - 1].value
            expression = previous in {b'return', b'co_return', b'=', b',', b'?'}
            if previous == b'(':
                opening = i - 1
                while opening > 0 and tokens[opening - 1].value == b'(':
                    opening -= 1
                head = tokens[opening - 1] if opening > 0 else None
                # Exclude primitive/type syntax and decltype (which already
                # parses operator identifiers), allow a normal call expression.
                expression = head is not None and head.kind == 'identifier' and head.value not in {
                    b'decltype', b'sizeof', b'alignof', b'int', b'char', b'void', b'long', b'short', b'float', b'double'}
            if expression:
                self.replace(shadow, token.start, tokens[ending - 1].end, 'operator-id', b'_nso_op')
        self.cpp_template_destructors(shadow)
        self.cpp_anonymous_enums(shadow)

    def cpp_anonymous_enums(self, shadow):
        # A legal unscoped anonymous enum with a fixed underlying type has a
        # missing name in the pinned grammar.  Validate the original base and
        # complete body in a named probe, then omit only :base from the parser
        # view.  The real enum stays anonymous and its type is marked unknown.
        tokens = self.tokens
        starts = {token.start: i for i, token in enumerate(tokens)}
        tree = self.parser.parse(bytes(shadow))
        integer_words = {b'bool', b'char', b'signed', b'unsigned', b'short', b'int', b'long',
                         b'wchar_t', b'char8_t', b'char16_t', b'char32_t', b'__int128'}
        excluded = (_PACK_LABEL_KEYWORDS | set(_KEYWORD_ALIASES) | _NULLABILITY | _TYPEOF | {
            b'__underlying_type', b'__func__', b'__FUNCTION__', b'__PRETTY_FUNCTION__'}) - integer_words
        for node in _walk(tree.root_node):
            if node.type != 'enum_specifier':
                continue
            name, base, body = (node.child_by_field_name(field) for field in ('name', 'base', 'body'))
            errors = [n for n in _walk_all(node) if n.type == 'ERROR' or n.is_missing]
            if (name is None or name.type != 'type_identifier' or not name.is_missing
                    or errors != [name] or base is None or body is None or body.type != 'enumerator_list'
                    or base.has_error or body.has_error
                    or base.type not in {'primitive_type', 'sized_type_specifier'}):
                continue
            index = starts.get(node.start_byte)
            if (index is None or index + 2 >= len(tokens) or tokens[index].value != b'enum'
                    or tokens[index + 1].value != b':' or tokens[index + 2].start != base.start_byte):
                continue
            base_tokens, cursor = [], index + 2
            while cursor < len(tokens) and tokens[cursor].start < base.end_byte:
                base_tokens.append(tokens[cursor])
                cursor += 1
            if not base_tokens or base_tokens[-1].end != base.end_byte:
                continue
            named_base = all(token.kind == 'identifier' and token.value in integer_words for token in base_tokens)
            if not named_base:
                cursor = 0
                if len(base_tokens) >= 2 and [t.value for t in base_tokens[:2]] == [b':', b':']:
                    cursor = 2
                while cursor < len(base_tokens):
                    token = base_tokens[cursor]
                    if token.kind != 'identifier' or token.value in excluded:
                        break
                    cursor += 1
                    if cursor == len(base_tokens):
                        named_base = True
                        break
                    if [t.value for t in base_tokens[cursor:cursor + 2]] != [b':', b':']:
                        break
                    cursor += 2
            if not named_base:
                continue
            raw_base = self.source[base.start_byte:base.end_byte]
            raw_body = self.source[body.start_byte:body.end_byte]
            probe = self.parser.parse(b'enum _nso_enum_probe : ' + raw_base + b' ' + raw_body + b';\n')
            if probe.root_node.has_error:
                continue
            enums = [n for n in _walk(probe.root_node) if n.type == 'enum_specifier']
            if len(enums) != 1 or enums[0].child_by_field_name('base') is None or enums[0].child_by_field_name('body') is None:
                continue
            start, end = tokens[index + 1].start, base.end_byte
            self.replace(shadow, start, end, 'anonymous-enum-base')
            self.regions[-1].update(enum_start=node.start_byte, enum_end=node.end_byte,
                                    base_start=base.start_byte, base_end=base.end_byte,
                                    body_start=body.start_byte, body_end=body.end_byte)

    def cpp_template_destructors(self, shadow):
        # The pinned grammar reads .~Local<Value>() as two comparisons, with a
        # missing expression in ().  Validate a named template argument list
        # and the complete projected member call; hide only <Value>, retaining
        # the receiver, destructor name and empty argument list.  These names
        # remain compiler/type safety contexts, never inferred object layouts.
        tokens = self.tokens
        starts = {token.start: i for i, token in enumerate(tokens)}
        tree = self.parser.parse(bytes(shadow))
        type_probes = {}
        excluded = _PACK_LABEL_KEYWORDS | set(_KEYWORD_ALIASES) | _NULLABILITY | _TYPEOF | {
            b'__underlying_type', b'__func__', b'__FUNCTION__', b'__PRETTY_FUNCTION__'}
        for node in _walk(tree.root_node):
            if node.type != 'destructor_name' or node.parent is None or node.parent.type != 'field_expression':
                continue
            field = node.parent
            operator = field.child_by_field_name('operator')
            if (field.child_by_field_name('field') != node or operator is None
                    or self.source[operator.start_byte:operator.end_byte] not in {b'.', b'->'}):
                continue
            index = starts.get(node.start_byte)
            if (index is None or index + 2 >= len(tokens) or tokens[index].value != b'~'
                    or tokens[index + 1].kind != 'identifier' or tokens[index + 1].end != node.end_byte
                    or tokens[index + 2].value != b'<'):
                continue
            opening, cursor = index + 2, index + 3
            named_arguments = True
            while cursor < len(tokens):
                # A simple (possibly qualified) name only: no values, nested
                # templates, decltype/typeof, literals or function operands can
                # disappear behind this projection.
                if cursor + 1 < len(tokens) and [t.value for t in tokens[cursor:cursor + 2]] == [b':', b':']:
                    cursor += 2
                if cursor >= len(tokens) or tokens[cursor].kind != 'identifier' or tokens[cursor].value in excluded:
                    named_arguments = False
                    break
                cursor += 1
                while cursor + 1 < len(tokens) and [t.value for t in tokens[cursor:cursor + 2]] == [b':', b':']:
                    cursor += 2
                    if cursor >= len(tokens) or tokens[cursor].kind != 'identifier' or tokens[cursor].value in excluded:
                        named_arguments = False
                        break
                    cursor += 1
                if not named_arguments or cursor >= len(tokens) or tokens[cursor].value != b',':
                    break
                cursor += 1
            if (not named_arguments or cursor + 2 >= len(tokens) or tokens[cursor].value != b'>'
                    or tokens[cursor + 1].value != b'(' or self.pairs.get(cursor + 1) != cursor + 2):
                continue
            start, end = tokens[opening].start, tokens[cursor].end
            template = self.source[tokens[index + 1].start:end]
            if template not in type_probes:
                probe = self.parser.parse(b'using _nso_destructor_type_probe = ' + template + b';\n')
                arguments = next((n for n in _walk(probe.root_node) if n.type == 'template_argument_list'), None)
                types = [n for n in arguments.named_children if n.type != 'comment'] if arguments is not None else []
                type_probes[template] = (not probe.root_node.has_error and bool(types)
                                        and all(n.type == 'type_descriptor' for n in types))
            if not type_probes[template]:
                continue
            finish = tokens[cursor + 2].end
            projected = (bytes(shadow[field.start_byte:start]) + _padded(self.source[start:end])
                         + bytes(shadow[end:finish]))
            probe = self.parser.parse(b'void _nso_destructor_call_probe(){' + projected + b';}\n')
            statements = [n for n in _walk(probe.root_node) if n.type == 'expression_statement']
            if probe.root_node.has_error or len(statements) != 1:
                continue
            expressions = [n for n in statements[0].named_children if n.type != 'comment']
            if len(expressions) != 1 or expressions[0].type != 'call_expression':
                continue
            call = expressions[0]
            function = call.child_by_field_name('function')
            arguments = call.child_by_field_name('arguments')
            destructor = function.child_by_field_name('field') if function is not None else None
            if (function is None or function.type != 'field_expression' or destructor is None
                    or destructor.type != 'destructor_name' or arguments is None
                    or any(n.type != 'comment' for n in arguments.named_children)):
                continue
            self.replace(shadow, start, end, 'template-destructor')

    def member_type_probe(self, source, at, require_type):
        tree = self.parser.parse(source)
        if tree.root_node.has_error:
            return False
        node = tree.root_node.descendant_for_byte_range(at, at + 1)
        chain = (node, *_parents(node))
        pointer = next((n for n in chain if n.type in {'abstract_pointer_declarator', 'pointer_declarator'}), None)
        if pointer is None:
            return False
        # A parseable binary expression is not a validated abstract type.
        if require_type and not any(n.type == 'type_descriptor' for n in chain):
            return False
        if any(n.type == 'init_declarator' and _contains(n.child_by_field_name('value'), node) for n in chain):
            return False
        return True

    def replace(self, shadow, start, end, kind, replacement=b'', names=()):
        shadow[start:end] = _padded(self.source[start:end], replacement)
        self.regions.append({'start': start, 'end': end, 'kind': kind, 'names': names})

    def attribute(self, start):
        tokens, pairs = self.tokens, self.pairs
        outer = start + 1
        if outer + 1 >= len(tokens) or tokens[outer].value != b'(' or tokens[outer + 1].value != b'(':
            return None
        end = pairs.get(outer)
        if end is None or pairs.get(outer + 1) != end - 1:
            return None
        i, names = outer + 2, []
        while i < end - 1:
            if tokens[i].kind != 'identifier':
                return None
            name = tokens[i].value.decode('ascii', errors='replace')
            if name.startswith('__') and name.endswith('__'):
                name = name[2:-2]
            if name not in _GNU_ATTRIBUTES:
                return None
            names.append(name)
            i += 1
            if i < end - 1 and tokens[i].value == b'(':
                argument_end = pairs.get(i)
                if argument_end is None or argument_end >= end - 1:
                    return None
                if any(t.kind == 'invalid' for t in tokens[i:argument_end + 1]):
                    return None
                i = argument_end + 1
            if i < end - 1:
                if tokens[i].value != b',':
                    return None
                i += 1
                if i == end - 1:
                    return None
        return end, tuple(names)

    def bind_regions(self):
        """A blanked prefix/postfix still belongs to the declaration/type.

        Most extensions lie inside node byte ranges.  Prefix attributes and
        attributes following an aggregate's closing brace do not, so explicitly
        attach them to the adjacent declaration or completed aggregate as well.
        """
        tokens = self.tokens
        starts = [t.start for t in tokens]
        owners = {'declaration', 'type_definition', 'field_declaration', 'parameter_declaration',
                  'optional_parameter_declaration', 'function_definition', 'struct_specifier',
                  'union_specifier', 'class_specifier', 'enum_specifier'}
        for region in self.regions:
            if region['kind'] not in {'attribute', 'nullability', 'asm-declarator'}:
                continue
            index = bisect_right(starts, region['start']) - 1
            while index >= 0 and tokens[index].end > region['start']:
                index -= 1
            after = bisect_right(starts, region['end'] - 1)
            if after < len(tokens):
                following = tokens[after]
                node = self.tree.root_node.descendant_for_byte_range(following.start, following.end)
                for parent in (node, *_parents(node)):
                    if parent.type in owners and parent.start_byte >= region['end']:
                        self.attachments.setdefault(parent.id, []).append(region)
                        break
            if index >= 0 and tokens[index].value == b'}':
                previous = tokens[index]
                node = self.tree.root_node.descendant_for_byte_range(previous.start, previous.end)
                for parent in (node, *_parents(node)):
                    if parent.type in {'struct_specifier', 'union_specifier', 'class_specifier', 'enum_specifier'} and parent.end_byte == previous.end:
                        self.attachments.setdefault(parent.id, []).append(region)
                        break

    def bind_cpp_regions(self):
        if self.language != 'cpp':
            return
        for region in self.regions:
            if region['kind'] == 'anonymous-enum-base':
                node = self.tree.root_node.descendant_for_byte_range(region['enum_start'], region['enum_end'])
                chain = (node, *_parents(node))
                owner = next((n for n in chain if n.type == 'enum_specifier'
                              and n.start_byte == region['enum_start'] and n.end_byte == region['enum_end']), None)
                body = owner.child_by_field_name('body') if owner is not None else None
                if (owner is None or owner.child_by_field_name('name') is not None
                        or owner.child_by_field_name('base') is not None or body is None
                        or (body.start_byte, body.end_byte) != (region['body_start'], region['body_end'])):
                    raise Unsupported('cpp_anonymous_enum_context')
                self.attachments.setdefault(owner.id, []).append(region)
                continue
            if region['kind'] not in {'deleted-function', 'member-pointer', 'operator-id', 'template-destructor'}:
                continue
            at = region['end'] if region['kind'] == 'member-pointer' else region['start']
            node = self.tree.root_node.descendant_for_byte_range(at, min(at + 1, len(self.source)))
            chain = (node, *_parents(node))
            if region['kind'] == 'deleted-function':
                owner = next((n for n in chain if n.type in {'declaration', 'field_declaration', 'function_definition'}), None)
                if owner is not None:
                    self.attachments.setdefault(owner.id, []).append(region)
            elif region['kind'] == 'member-pointer':
                owner = next((n for n in chain if n.type in {'type_descriptor', 'type_definition', 'alias_declaration',
                                                            'parameter_declaration', 'field_declaration', 'declaration'}), None)
                if owner is not None:
                    self.type_contexts.setdefault(owner.id, []).append(region)
            else:
                owner = next((n for n in chain if n.type == 'call_expression'), None)
                if region['kind'] == 'template-destructor':
                    function = owner.child_by_field_name('function') if owner is not None else None
                    destructor = function.child_by_field_name('field') if function is not None else None
                    if (function is None or function.type != 'field_expression' or destructor is None
                            or destructor.type != 'destructor_name'):
                        raise Unsupported('cpp_template_destructor_context')
                if owner is not None:
                    self.attachments.setdefault(owner.id, []).append(region)

    def attached(self, node, kind):
        return any(r['kind'] == kind for r in self.attachments.get(node.id, ()))

    def within(self, node, kinds=None):
        if node is None:
            return []
        return [r for r in self.regions if (kinds is None or r['kind'] in kinds)
                and r['start'] < node.end_byte and node.start_byte < r['end']]

    def attributes(self, node):
        kinds = {'attribute', 'nullability', 'asm-declarator'}
        return bool(self.within(node, kinds) or any(self.attached(n, kind) for n in _walk(node) for kind in kinds))

    def hidden_tokens(self, region):
        start = bisect_right(self.starts, region['start']) - 1
        end = bisect_right(self.starts, region['end'] - 1)
        return self.tokens[max(0, start):end]

    def summary(self):
        return {'byte_offsets_preserved': len(self.view) == len(self.source),
                'shadow_sha256': hashlib.sha256(self.view).hexdigest(),
                'normalized_regions': len(self.regions),
                'kind_counts': {kind: sum(r['kind'] == kind for r in self.regions)
                                for kind in sorted({r['kind'] for r in self.regions})},
                'attribute_name_counts': {name: sum(name in r['names'] for r in self.regions)
                                          for name in sorted({n for r in self.regions for n in r['names']})}}


def _walk_all(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _parents(node):
    current = node.parent
    while current is not None:
        yield current
        current = current.parent


def _contains(parent, child):
    return parent is not None and parent.start_byte <= child.start_byte and child.end_byte <= parent.end_byte


def _scope(node):
    return tuple(p.id for p in reversed(list(_parents(node))) if p.type in SCOPE_TYPES)


def _name_node(declarator):
    current = declarator
    while current is not None:
        if current.type in {'identifier', 'field_identifier', 'type_identifier', 'qualified_identifier'}:
            return current
        child = current.child_by_field_name('declarator')
        if child is None and current.type == 'parenthesized_declarator':
            child = next((c for c in current.named_children if c.type != 'attribute_specifier'), None)
        current = child
    return None


def _integer(raw):
    text = raw.decode('ascii').replace("'", '')
    text = re.sub(r'[uUlL]+$', '', text)
    if not re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)', text):
        raise Unsupported('nonliteral_integer')
    if text.lower().startswith('0x'):
        return int(text, 16)
    if text.lower().startswith('0b'):
        return int(text, 2)
    if len(text) > 1 and text.startswith('0'):
        return int(text, 8)
    return int(text, 10)


def _decode_ordinary(raw):
    if not raw.startswith(b'"') or not raw.endswith(b'"'):
        raise Unsupported('nonordinary_literal_encoding')
    body = raw[1:-1]
    output = bytearray()
    simple = {ord('a'): 7, ord('b'): 8, ord('f'): 12, ord('n'): 10,
              ord('r'): 13, ord('t'): 9, ord('v'): 11, ord('e'): 27,
              ord('\\'): 92, ord('"'): 34, ord("'"): 39, ord('?'): 63}
    i = 0
    while i < len(body):
        value = body[i]
        i += 1
        if value != 92:
            output.append(value)
            continue
        if i == len(body):
            raise Unsupported('unterminated_escape')
        value = body[i]
        i += 1
        if value in simple:
            output.append(simple[value])
        elif value in (10, 13):
            if value == 13 and i < len(body) and body[i] == 10:
                i += 1
        elif 48 <= value <= 55:
            digits = bytes([value])
            while i < len(body) and len(digits) < 3 and 48 <= body[i] <= 55:
                digits += bytes([body[i]])
                i += 1
            number = int(digits, 8)
            if number > 255:
                raise Unsupported('out_of_range_escape')
            output.append(number)
        elif value == ord('x'):
            start = i
            while i < len(body) and body[i] in b'0123456789abcdefABCDEF':
                i += 1
            if i == start:
                raise Unsupported('empty_hex_escape')
            number = int(body[start:i], 16)
            if number > 255:
                raise Unsupported('out_of_range_escape')
            output.append(number)
        elif value in (ord('u'), ord('U')):
            count = 4 if value == ord('u') else 8
            digits = body[i:i + count]
            if len(digits) != count or any(c not in b'0123456789abcdefABCDEF' for c in digits):
                raise Unsupported('invalid_universal_escape')
            try:
                output.extend(chr(int(digits, 16)).encode('utf-8'))
            except (ValueError, UnicodeError) as error:
                raise Unsupported('invalid_universal_escape') from error
            i += count
        else:
            raise Unsupported('unsupported_escape')
    return bytes(output)


def _literal_bytes(node, source):
    if node.type == 'concatenated_string':
        return b''.join(_literal_bytes(c, source) for c in node.named_children if c.type != 'comment')
    if node.type == 'raw_string_literal':
        raw = source[node.start_byte:node.end_byte]
        if not raw.startswith(b'R"'):
            raise Unsupported('nonordinary_literal_encoding')
        content = next((c for c in node.named_children if c.type == 'raw_string_content'), None)
        return b'' if content is None else source[content.start_byte:content.end_byte]
    return _decode_ordinary(source[node.start_byte:node.end_byte])


def _marker_status(value):
    if b'frida' not in value.lower():
        return None
    without_weekday = re.sub(rb'(?<![a-zA-Z0-9_])friday(?![a-zA-Z0-9_])', b'', value, flags=re.I)
    return 'ordinary_friday' if b'frida' not in without_weekday.lower() else 'target'


def _shape(kind='unknown', **kwargs):
    result = dict(kind=kind, const=False, const_nodes=[], unsafe=None, packing_dependent=False)
    result.update(kwargs)
    return result


class Transformer:
    def __init__(self, source, language, filename, cpp_opaque_roots=()):
        self.source = source
        self.language = language
        self.filename = filename
        self.cpp_opaque_roots = tuple(cpp_opaque_roots)
        self.prefix = 'nso_' + hashlib.sha256(source).hexdigest()[:16]
        while self.prefix.encode() in source:
            self.prefix += 'x'
        self.report = {
            'schema_version': 1, 'mode': 'preprocessed-source-ast-xor',
            'language': language, 'input': filename, 'ok': False,
            'input_sha256': hashlib.sha256(source).hexdigest(),
            'parser_dependencies': dict(PARSER_PINS), 'xor_key': XOR_KEY,
            'constructor_priority': 101, 'entries': [], 'occurrences': [],
            'static_objects': [], 'skipped': [], 'failures': [],
            'assumptions': ['UTF-8 execution character set',
                            'GNU C/C++ constructor/typeof/trap support',
                            'existing GLib allocation/once declarations',
                            'constructors of consumers run after priority 101'],
        }
        self.edits = []
        self.edit_keys = set()
        self.entries = []
        self.literal_entries = {}
        self.type_records = {}
        self.type_cache = {}
        self.type_context = None
        self.packing_ranges = []
        self.variables = []
        self.functions = {}
        self.initializer_map = {}
        self.objects = {}
        self.skipped_nodes = set()
        self.transformed_nodes = set()
        self.resource_nodes = set()
        self.literal_candidates = 0
        self.resource_candidates = 0
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_c
            import tree_sitter_cpp
            actual = {name: importlib.metadata.version(name) for name in PARSER_PINS}
            if actual != PARSER_PINS:
                self.fail('parser_version_mismatch', repr(actual))
            grammar = tree_sitter_c if language == 'c' else tree_sitter_cpp
            self.parser = Parser(Language(grammar.language()))
        except (ImportError, importlib.metadata.PackageNotFoundError) as error:
            self.fail('parser_dependency_missing', str(error))
        if self.cpp_opaque_roots and language != 'cpp':
            self.fail('cpp_opaque_policy_requires_cpp')
        try:
            self.shadow = _ParserShadow(source, language, self.parser, self.cpp_opaque_roots)
        except Unsupported as error:
            self.fail(str(error))
        self.tree = self.shadow.tree
        self.root = self.tree.root_node
        self.nodes = list(_walk(self.root))
        self.report['parser_normalization'] = self.shadow.summary()
        if self.cpp_opaque_roots:
            self.report['cpp_header_boundary'] = self.shadow.origins.summary()

    def text(self, node):
        return '' if node is None else self.source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def location(self, node):
        return {'start_byte': node.start_byte, 'end_byte': node.end_byte,
                'line': node.start_point.row + 1, 'column': node.start_point.column + 1}

    def fail(self, reason, detail='', node=None):
        item = {'reason': reason, 'detail': detail}
        if node is not None:
            item.update(self.location(node))
        self.report['failures'].append(item)
        raise OutlineError(reason + (': ' + detail if detail else ''), self.report)

    def skip(self, node, reason, kind='string', detail=''):
        key = (node.start_byte, node.end_byte, kind)
        if key in self.skipped_nodes:
            return
        self.skipped_nodes.add(key)
        self.report['skipped'].append(dict(self.location(node), kind=kind, reason=reason, detail=detail))

    def skip_region(self, start, end, reason, kind='string', detail=''):
        key = (start, end, kind)
        if key in self.skipped_nodes:
            return
        self.skipped_nodes.add(key)
        line = self.source.count(b'\n', 0, start) + 1
        column = start - (self.source.rfind(b'\n', 0, start) + 1) + 1
        self.report['skipped'].append({'start_byte': start, 'end_byte': end,
                                       'line': line, 'column': column,
                                       'kind': kind, 'reason': reason, 'detail': detail})

    def hidden_syntax(self):
        # Masking a compiler annotation/type operand is not permission to lose
        # its literals, __func__, or resource uses from the safety analysis.
        literals = set()
        for region in self.shadow.origins.ranges:
            tokens = _lex(self.source[region['start']:region['end']])
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token.kind != 'string':
                    i += 1
                    continue
                end = i + 1
                while end < len(tokens) and tokens[end].kind == 'string':
                    end += 1
                start_byte = region['start'] + token.start
                end_byte = region['start'] + tokens[end - 1].end
                try:
                    value = b''.join(_decode_ordinary(t.value) for t in tokens[i:end])
                    status = _marker_status(value)
                except Unsupported:
                    status = 'target' if b'frida' in self.source[start_byte:end_byte].lower() else None
                if status is not None:
                    self.literal_candidates += 1
                    self.skip_region(start_byte, end_byte, 'skipped_header_origin',
                                     detail=', '.join(region['origins']))
                i = end
            for token in tokens:
                if token.kind == 'identifier' and RESOURCE_NAME.fullmatch(token.value.decode('ascii', errors='replace')):
                    start = region['start'] + token.start
                    self.skip_region(start, region['start'] + token.end, 'skipped_header_origin',
                                     'numeric-resource', ', '.join(region['origins']))
        for region in self.shadow.regions:
            if region['kind'] not in {'attribute', 'typeof', 'builtin-type', 'asm-declarator', 'template-destructor', 'anonymous-enum-base', 'anonymous-bitfield-type'}:
                continue
            reason = {'attribute': 'attribute_context', 'typeof': 'compile_time_or_type_context',
                      'builtin-type': 'compile_time_or_type_context', 'asm-declarator': 'assembly_context',
                      'template-destructor': 'compile_time_or_type_context',
                      'anonymous-enum-base': 'compile_time_or_type_context',
                      'anonymous-bitfield-type': 'compile_time_or_type_context'}[region['kind']]
            tokens = self.shadow.hidden_tokens(region)
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token.kind == 'string':
                    end = i + 1
                    while end < len(tokens) and tokens[end].kind == 'string':
                        end += 1
                    key = (token.start, tokens[end - 1].end)
                    if key not in literals:
                        literals.add(key)
                        try:
                            value = b''.join(_decode_ordinary(t.value) for t in tokens[i:end])
                            status = _marker_status(value)
                        except Unsupported:
                            status = 'target' if b'frida' in self.source[key[0]:key[1]].lower() else None
                        if status is not None:
                            self.literal_candidates += 1
                            self.skip_region(*key, 'ordinary_friday' if status == 'ordinary_friday' else reason)
                    i = end
                else:
                    i += 1

    def edit(self, start, end, replacement):
        if isinstance(replacement, str):
            replacement = replacement.encode('utf-8')
        key = (start, end, replacement)
        if key not in self.edit_keys:
            self.edit_keys.add(key)
            self.edits.append((start, end, replacement))

    def namespace(self, node):
        parts = []
        for parent in reversed(list(_parents(node))):
            if parent.type == 'namespace_definition':
                name = parent.child_by_field_name('name')
                if name is not None:
                    parts.append(self.text(name))
        return parts

    def qualified(self, node, name):
        parts = self.namespace(node) + [name]
        return ('::' if self.language == 'cpp' else '') + '::'.join(parts)

    def header_symbol_unknown(self, name):
        if self.language != 'cpp':
            return False
        leaf = name.encode('utf-8').rsplit(b'::', 1)[-1].strip()
        return leaf in self.shadow.origins.symbols

    def _lookup_type_record(self, node, name, position=None, aggregate_kind=None):
        # A hidden namespace typedef can shadow an otherwise visible owned
        # declaration.  Its real qualifiers/layout cannot be inferred from the
        # owned homonym; keep this type unknown rather than falling back.
        if self.header_symbol_unknown(name):
            return None
        scope = _scope(node)
        records = self.type_records.get(name, [])
        position = node.start_byte if position is None else position
        visible = [r for r in records if r['start'] <= position
                   and scope[:len(r['scope'])] == r['scope']
                   and (aggregate_kind is None or r['node'].type == aggregate_kind)]
        if not visible:
            return None
        return max(visible, key=lambda r: (len(r['scope']), r['start']))

    def collect_types(self):
        for node in self.nodes:
            if node.type in {'struct_specifier', 'union_specifier', 'class_specifier'}:
                name = node.child_by_field_name('name')
                body = node.child_by_field_name('body')
                if name is not None and body is not None:
                    self.type_records.setdefault(self.text(name), []).append({
                        'node': node, 'declarator': None, 'scope': _scope(node), 'start': node.start_byte})
            elif node.type == 'type_definition':
                for declarator in node.children_by_field_name('declarator'):
                    name = _name_node(declarator)
                    if name is not None:
                        self.type_records.setdefault(self.text(name), []).append({
                            'node': node, 'declarator': declarator, 'scope': _scope(node), 'start': node.start_byte})

    def qualifiers(self, container, base):
        result = copy.copy(base)
        const_nodes = [c for c in container.named_children if c.type == 'type_qualifier' and self.text(c) == 'const']
        if const_nodes:
            result['const'] = True
            result['const_nodes'] = const_nodes
        return result

    def attributes(self, node):
        return self.shadow.attributes(node) or any(c.type in _ATTRIBUTE_NODE_TYPES for c in _walk(node))

    def base_type(self, node):
        if (node is not None and node.type in {'struct_specifier', 'union_specifier', 'class_specifier'}
                and node.child_by_field_name('body') is not None):
            key = ('aggregate', node.id)
            if key in self.type_cache:
                return self.type_cache[key]
            # Real Linux/GLib headers contain self-referential tagged structs;
            # their pointer fields must not recurse indefinitely during layout
            # collection.  An unresolved recursive member stays unsafe.
            self.type_cache[key] = _shape(unsafe='recursive_type')
            result = self._base_type(node)
            self.type_cache[key] = result
            return result
        return self._base_type(node)

    def _base_type(self, node):
        if node is None:
            return _shape()
        body = (node.child_by_field_name('body')
                if node.type in {'struct_specifier', 'union_specifier', 'class_specifier'} else None)
        # Hidden compiler syntax may make the aggregate itself unknown, but
        # cannot erase its by-value packing dependency from an outer object.
        if body is not None and self.aggregate_packing_dependent(node, body):
            return _shape(unsafe='aggregate_pragma_packing', packing_dependent=True)
        if self.shadow.within(node, {'typeof'}):
            return _shape(unsafe='compiler_inferred_type')
        if self.shadow.attached(node, 'anonymous-bitfield-type'):
            return _shape(unsafe='c_anonymous_bitfield_type')
        if self.shadow.within(node, {'member-pointer'}) or node.id in self.shadow.type_contexts:
            return _shape(unsafe='cpp_member_pointer_type')
        if node.type in {'primitive_type', 'sized_type_specifier'}:
            name = ' '.join(self.shadow.view[node.start_byte:node.end_byte].decode('utf-8').split())
            if name in {'char', 'signed char', 'unsigned char'}:
                return _shape('byte', spelling=name)
            if name == 'void':
                return _shape('void', spelling='void')
            return _shape('scalar', spelling=name)
        if node.type == 'enum_specifier':
            if self.shadow.attached(node, 'anonymous-enum-base'):
                return _shape(unsafe='cpp_fixed_underlying_anonymous_enum')
            return _shape('scalar', spelling=self.text(node))
        if node.type in {'type_identifier', 'qualified_identifier'}:
            record = self._lookup_type_record(node, self.text(node))
            if record is None:
                return _shape(unsafe='unresolved_type')
            key = (record['node'].id, record['declarator'].id if record['declarator'] is not None else 0)
            if key in self.type_cache:
                return self.type_cache[key]
            self.type_cache[key] = _shape(unsafe='recursive_type')
            if record['declarator'] is None:
                result = self.base_type(record['node'])
            else:
                result = self.declared_type(record['node'], record['declarator'])
            if result.get('unsafe') == 'unresolved_aggregate_type':
                # A forward typedef can become complete before a later use.
                self.type_cache.pop(key, None)
            else:
                self.type_cache[key] = result
            return result
        if node.type in {'struct_specifier', 'union_specifier', 'class_specifier'}:
            body = node.child_by_field_name('body')
            if body is None:
                name = node.child_by_field_name('name')
                position = self.type_context.start_byte if self.type_context is not None else node.start_byte
                record = self._lookup_type_record(node, self.text(name), position, node.type) if name is not None else None
                return self.base_type(record['node']) if record is not None and record['node'] != node else _shape(unsafe='unresolved_aggregate_type')
            if node.type != 'struct_specifier':
                return _shape(unsafe='union_or_class_layout')
            if any(c.type == 'base_class_clause' for c in node.named_children):
                return _shape(unsafe='nontrivial_cpp_aggregate')
            if self.attributes(node):
                return _shape(unsafe='aggregate_attributes_or_packing')
            fields = []
            for field in body.named_children:
                if field.type != 'field_declaration':
                    return _shape(unsafe='nontrivial_cpp_aggregate')
                if any(c.type == 'bitfield_clause' for c in field.named_children):
                    return _shape(unsafe='bitfield_aggregate')
                declarators = field.children_by_field_name('declarator')
                if not declarators:
                    return _shape(unsafe='anonymous_aggregate_field')
                for declarator in declarators:
                    name = _name_node(declarator)
                    if name is None:
                        return _shape(unsafe='unnamed_aggregate_field')
                    if any(c.type == 'storage_class_specifier' for c in field.named_children):
                        return _shape(unsafe='nontrivial_cpp_aggregate')
                    fields.append((self.text(name), self.declared_type(field, declarator)))
            return _shape('struct', fields=fields)
        return _shape(unsafe='unresolved_type')

    def apply_declarator(self, base, node):
        if node is None or node.type in {'identifier', 'field_identifier', 'type_identifier', 'qualified_identifier'}:
            return base
        child = node.child_by_field_name('declarator')
        if node.type == 'init_declarator':
            return self.apply_declarator(base, child)
        if node.type in {'pointer_declarator', 'abstract_pointer_declarator'}:
            result = self.qualifiers(node, _shape('pointer', pointee=base, unsafe=base.get('unsafe')))
            return self.apply_declarator(result, child)
        if node.type in {'array_declarator', 'abstract_array_declarator'}:
            count = None
            size = node.child_by_field_name('size')
            if size is not None:
                try:
                    count = _integer(self.source[size.start_byte:size.end_byte])
                except (Unsupported, ValueError, UnicodeError):
                    pass
            return self.apply_declarator(_shape('array', element=base, count=count, size_node=size,
                                                 unsafe=base.get('unsafe'),
                                                 packing_dependent=base.get('packing_dependent', False)), child)
        if node.type in {'function_declarator', 'abstract_function_declarator'}:
            result = _shape('function', returns=base, parameters=node.child_by_field_name('parameters'))
            return self.apply_declarator(result, child)
        if node.type == 'parenthesized_declarator':
            child = next((c for c in node.named_children if c.type != 'attribute_specifier'), None)
            return self.apply_declarator(base, child)
        return _shape(unsafe='unsupported_declarator')

    def declared_type(self, declaration, declarator):
        if self.shadow.attached(declaration, 'anonymous-bitfield-type'):
            return _shape(unsafe='c_anonymous_bitfield_type')
        if (declaration.id in self.shadow.type_contexts
                or self.shadow.within(declarator, {'member-pointer'})):
            return _shape(unsafe='cpp_member_pointer_type')
        previous_context = self.type_context
        if previous_context is None:
            self.type_context = declaration
        try:
            base = self.qualifiers(declaration, self.base_type(declaration.child_by_field_name('type')))
            result = self.apply_declarator(base, declarator)
        finally:
            self.type_context = previous_context
        # An attribute on a typedef/field changes the assumptions of *every*
        # object using that type, even when its parser-shadow spelling is blank.
        if declaration.type in {'type_definition', 'field_declaration', 'parameter_declaration', 'optional_parameter_declaration'} and self.attributes(declaration):
            result = copy.copy(result)
            result['unsafe'] = 'type_or_field_attributes'
        return result

    def collect_variables_and_functions(self):
        for node in self.nodes:
            if node.type not in {'declaration', 'function_definition', 'parameter_declaration', 'optional_parameter_declaration'}:
                continue
            for declarator in node.children_by_field_name('declarator'):
                name_node = _name_node(declarator)
                if name_node is None:
                    continue
                name = self.text(name_node)
                shape = self.declared_type(node, declarator)
                if shape['kind'] == 'function':
                    self.functions.setdefault(name, []).append((node, shape))
                    continue
                if shape['kind'] == 'pointer' and shape['pointee']['kind'] == 'function':
                    self.functions.setdefault(name, []).append((node, shape['pointee']))
                    continue
                value = declarator.child_by_field_name('value') if declarator.type == 'init_declarator' else None
                function = next((p for p in _parents(node) if p.type == 'function_definition'), None)
                storage = {self.text(c) for c in node.named_children if c.type == 'storage_class_specifier'}
                variable = {'node': node, 'declarator': declarator, 'name_node': name_node,
                            'name': name, 'qualified': self.qualified(node, name), 'shape': shape,
                            'value': value, 'function': function, 'storage': storage, 'scope': _scope(node),
                            'static': function is None or 'static' in storage}
                self.variables.append(variable)
                if value is not None:
                    leaves = []
                    # Object storage const may be removed; const aggregate members
                    # and pointee const must never be removed or written through.
                    layout = self.mutable_storage_shape(shape)
                    self.map_initializer(value, layout, '', False, leaves)
                    paths = [leaf[1] for leaf in leaves if leaf[3] is None]
                    duplicate = len(paths) != len(set(paths))
                    for leaf, path, leafshape, reason in leaves:
                        self.initializer_map[leaf.id] = (variable, path, leafshape,
                                                        'overlapping_designated_initializers' if duplicate else reason)

    def mutable_storage_shape(self, shape):
        result = copy.copy(shape)
        if shape['kind'] == 'array':
            result['element'] = self.mutable_storage_shape(shape['element'])
        else:
            result['const'] = False
            result['const_nodes'] = []
        return result

    def map_initializer(self, node, shape, path, immutable, leaves):
        if shape.get('unsafe'):
            for child in _walk(node):
                if child.type in LITERAL_TYPES or child.type == 'identifier':
                    leaves.append((child, path, shape, shape['unsafe']))
            return
        if shape['kind'] == 'array':
            immutable = immutable or False
        else:
            immutable = immutable or shape['const']
        if node.type in {'parenthesized_expression', 'cast_expression'}:
            inner = node.child_by_field_name('value')
            if inner is None and node.type == 'parenthesized_expression':
                inner = next((c for c in node.named_children if c.type != 'comment'), None)
            if inner is not None:
                self.map_initializer(inner, shape, path, immutable, leaves)
                return
        if node.type != 'initializer_list':
            reason = 'immutable_aggregate_member' if immutable else None
            if shape['kind'] == 'array':
                reason = 'char_array_literal' if node.type in LITERAL_TYPES and shape['element']['kind'] == 'byte' else 'brace_elision_or_array_value'
            elif shape['kind'] == 'struct':
                reason = 'brace_elision_or_aggregate_value'
            # The root object's const is removable; member const is not.
            leaves.append((node, path, shape, reason))
            if node.type not in LITERAL_TYPES and node.type not in {'identifier', 'qualified_identifier'}:
                for child in _walk(node):
                    if child.id != node.id and (child.type in LITERAL_TYPES or child.type == 'identifier'):
                        leaves.append((child, path, shape, reason or 'nonliteral_initializer_expression'))
            return
        items = [c for c in node.named_children if c.type != 'comment']
        if shape['kind'] not in {'array', 'struct'}:
            if len(items) == 1:
                self.map_initializer(items[0], shape, path, immutable, leaves)
            else:
                for item in items:
                    self.map_initializer(item, _shape(unsafe='unsupported_scalar_initializer'), path, immutable, leaves)
            return
        cursor = 0
        multi_designator = False
        for item in items:
            target = shape['element'] if shape['kind'] == 'array' else (shape['fields'][cursor][1] if cursor < len(shape['fields']) else _shape(unsafe='excess_aggregate_initializer'))
            subpath = path + ('[%d]' % cursor if shape['kind'] == 'array' else ('.' + shape['fields'][cursor][0] if cursor < len(shape['fields']) else ''))
            value = item
            member_immutable = immutable
            if item.type == 'initializer_pair':
                designators = item.children_by_field_name('designator')
                target = shape
                subpath = path
                if len(designators) > 1:
                    multi_designator = True
                try:
                    for index, designator in enumerate(designators):
                        member_immutable = member_immutable or target['const']
                        if designator.type == 'field_designator' and target['kind'] == 'struct':
                            field_name = self.text(designator.named_children[0])
                            field_index = next(i for i, pair in enumerate(target['fields']) if pair[0] == field_name)
                            if index == 0:
                                cursor = field_index
                            target = target['fields'][field_index][1]
                            subpath += '.' + field_name
                        elif designator.type == 'subscript_designator' and target['kind'] == 'array':
                            array_index = _integer(self.source[designator.named_children[0].start_byte:designator.named_children[0].end_byte])
                            if array_index < 0 or (target['count'] is not None and array_index >= target['count']):
                                raise Unsupported('out_of_bounds_designator')
                            if index == 0:
                                cursor = array_index
                            target = target['element']
                            subpath += '[%d]' % array_index
                        else:
                            raise Unsupported('unsupported_designator')
                    value = item.child_by_field_name('value')
                except (Unsupported, StopIteration, ValueError, IndexError):
                    target = _shape(unsafe='unsupported_designator')
                    value = item.child_by_field_name('value') or item
            elif multi_designator:
                target = _shape(unsafe='positional_after_nested_designator')
            self.map_initializer(value, target, subpath, member_immutable, leaves)
            cursor += 1

    def variable_for_initializer(self, node):
        if node.id in self.initializer_map:
            return self.initializer_map[node.id]
        for parent in _parents(node):
            if parent.id in self.initializer_map:
                return self.initializer_map[parent.id]
        return None

    def removable_const(self, variable):
        shape = variable['shape']
        while shape['kind'] == 'array':
            shape = shape['element']
        if not shape['const']:
            return [], None
        nodes = shape['const_nodes']
        if not nodes or any(not _contains(variable['node'], n) for n in nodes):
            return [], 'typedef_const_storage'
        if any(n.parent == variable['node'] for n in nodes) and len(variable['node'].children_by_field_name('declarator')) != 1:
            return [], 'multi_declarator_const_storage'
        redeclarations = [v for v in self.variables if v['name'] == variable['name'] and v['scope'] == variable['scope']]
        if len(redeclarations) > 1:
            return [], 'const_storage_redeclaration'
        return nodes, None

    def packing_problem(self, node):
        return any(start < node.end_byte and node.start_byte < end
                   for start, end in self.packing_ranges)

    def aggregate_packing_dependent(self, node, body):
        # Member and base types contribute their *object* layout.  Pointer and
        # function declarators clear packing_dependent; arrays retain it.  This
        # metadata must cross otherwise-unknown union/class/inheritance shells
        # so a sibling pointer slot cannot bypass the aggregate packing policy.
        if self.packing_problem(node):
            return True
        for clause in node.named_children:
            if clause.type == 'base_class_clause':
                for base in clause.named_children:
                    if base.type != 'access_specifier' and self.base_type(base).get('packing_dependent'):
                        return True
        for field in body.named_children:
            if field.type != 'field_declaration':
                continue
            if any(c.type == 'storage_class_specifier' and self.text(c) == 'static'
                   for c in field.named_children):
                continue
            declarators = field.children_by_field_name('declarator')
            if declarators:
                if any(self.declared_type(field, declarator).get('packing_dependent')
                       for declarator in declarators):
                    return True
            elif self.base_type(field.child_by_field_name('type')).get('packing_dependent'):
                return True
        return False

    def static_problem(self, variable):
        node = variable['node']
        if self.header_symbol_unknown(variable['name']):
            return 'static_reference_header_origin'
        if self.attributes(node):
            return 'static_storage_attributes'
        if any(self.text(c) in {'_Thread_local', 'thread_local', '__thread'} for c in node.named_children):
            return 'thread_local_storage'
        _, reason = self.removable_const(variable)
        if reason:
            return reason
        if variable['function'] is not None:
            if node.parent.type != 'compound_statement':
                return 'local_static_nonblock_declaration'
            body = node.parent
            gotos = [c for c in _walk(variable['function']) if c.type == 'goto_statement']
            for label in _walk(body):
                if label.type == 'case_statement' and label.start_byte >= node.end_byte:
                    switch = next((p for p in _parents(label) if p.type == 'switch_statement'), None)
                    if switch is not None and _contains(switch, node):
                        return 'local_static_switch_can_bypass_initialization'
                if label.type != 'labeled_statement' or label.start_byte < node.end_byte:
                    continue
                name = label.child_by_field_name('label')
                if name is None:
                    name = next((c for c in label.named_children if c.type in {'statement_identifier', 'identifier'}), None)
                for jump in gotos:
                    target = jump.child_by_field_name('label')
                    if target is None:
                        target = next((c for c in jump.named_children if c.type in {'statement_identifier', 'identifier'}), None)
                    if self.text(target) == self.text(name) and (jump.start_byte < node.start_byte or not _contains(body, jump)):
                        return 'local_static_goto_can_bypass_initialization'
            if any(self.text(c).lstrip().startswith('goto *') for c in gotos):
                return 'local_static_computed_goto'
        return None

    def compiletime_reason(self, node):
        # Enumerators and bitfield widths remain constant expressions even
        # when a nested sizeof would otherwise receive the generic context.
        if any(parent.type == 'enumerator' for parent in _parents(node)):
            return 'enum_value_compile_time_context'
        if any(parent.type == 'bitfield_clause' for parent in _parents(node)):
            return 'bitfield_width_compile_time_context'
        for parent in _parents(node):
            if parent.type in {'declaration', 'field_declaration', 'function_definition'} and self.shadow.attached(parent, 'deleted-function'):
                return 'deleted_function_context'
            if parent.id in self.shadow.type_contexts:
                return 'cpp_member_pointer_type_context'
            if parent.type == 'call_expression' and self.shadow.attached(parent, 'operator-id'):
                return 'cpp_explicit_operator_call'
            if parent.type == 'call_expression' and self.shadow.attached(parent, 'template-destructor'):
                return 'cpp_template_destructor_call'
            if parent.type in {'sizeof_expression', 'alignof_expression', 'alignof', 'offsetof_expression'}:
                return 'sizeof_or_alignment_context'
            if parent.type in {'gnu_asm_expression', 'asm_statement'}:
                return 'assembly_context'
            if parent.type in {'attribute_specifier', 'attribute_declaration', 'ms_declspec_modifier'}:
                return 'attribute_context'
            if parent.type in {'array_declarator', 'abstract_array_declarator'} and _contains(parent.child_by_field_name('size'), node):
                return 'array_bound_compile_time_context'
            if parent.type in {'static_assert_declaration', 'static_assert', 'decltype', 'decltype_specifier',
                               'noexcept', 'noexcept_expression', 'typeid_expression', 'type_descriptor',
                               'template_argument_list', 'generic_expression', 'generic_association'}:
                return 'compile_time_or_type_context'
            if parent.type == 'template_declaration':
                return 'template_context'
            if parent.type == 'user_defined_literal':
                return 'user_defined_literal'
            if parent.type in {'lambda_expression', 'optional_parameter_declaration', 'field_declaration', 'type_definition'}:
                return 'lambda_default_or_field_context'
            if parent.type in {'declaration', 'function_definition'}:
                if any(self.text(c) in {'constexpr', 'consteval', 'constinit'} for c in parent.named_children):
                    return 'constexpr_or_constinit_context'
            if parent.type == 'linkage_specification' and _contains(parent.child_by_field_name('value'), node):
                return 'language_linkage_context'
            if parent.type == 'case_statement' and _contains(parent.child_by_field_name('value'), node):
                return 'case_label_context'
            if parent.type == 'call_expression':
                name = self.text(parent.child_by_field_name('function'))
                if name in {'_Static_assert', 'static_assert', '__builtin_constant_p', '__builtin_choose_expr',
                            '__builtin_types_compatible_p', '__builtin_object_size', '__builtin_dynamic_object_size',
                            '_Generic'}:
                    return 'compile_time_builtin_context'
        return None

    def cpp_call_problem(self, node):
        if self.language != 'cpp':
            return None
        for parent in _parents(node):
            if parent.type != 'call_expression':
                continue
            arguments = parent.child_by_field_name('arguments')
            if not _contains(arguments, node):
                continue
            items = [c for c in arguments.named_children if c.type != 'comment']
            index = next((i for i, c in enumerate(items) if _contains(c, node)), None)
            if any(p.type == 'subscript_expression' and _contains(p.child_by_field_name('argument'), node)
                   for p in _parents(node) if _contains(arguments, p)):
                # The call receives the already indexed byte/scalar, not the
                # array expression itself; decaying the array keeps that type.
                return None
            callee = self.text(parent.child_by_field_name('function'))
            # Hidden header overloads may win over an owned signature (notably
            # array-reference vs pointer overloads).  Decaying a literal or a
            # numeric resource must not change that choice.
            if self.header_symbol_unknown(callee):
                return 'cpp_header_origin_call_parameter'
            signatures = self.functions.get(callee, [])
            if not signatures or index is None:
                return 'unresolved_cpp_call_parameter'
            for declaration, signature in signatures:
                if self.shadow.attached(declaration, 'deleted-function'):
                    return 'cpp_deleted_call_parameter'
                if any(p.type == 'template_declaration' for p in _parents(declaration)):
                    return 'cpp_template_call_parameter'
                params = signature['parameters']
                fixed = [c for c in params.named_children if c.type in {'parameter_declaration', 'optional_parameter_declaration'}]
                if index >= len(fixed):
                    if not any(c.type == '...' or c.type == 'variadic_parameter' for c in params.children):
                        return 'unresolved_cpp_call_parameter'
                    continue
                parameter = fixed[index]
                declarator = parameter.child_by_field_name('declarator')
                shape = self.declared_type(parameter, declarator)
                if shape['kind'] == 'array':
                    shape = _shape('pointer', pointee=shape['element'])
                if shape['kind'] != 'pointer' or shape['pointee']['kind'] not in {'byte', 'void'}:
                    return 'cpp_nonpointer_call_parameter'
                if shape.get('unsafe') or shape['pointee'].get('unsafe'):
                    return 'cpp_attributed_or_unknown_call_parameter'
            return None
        return None

    def context(self, node):
        reason = self.compiletime_reason(node)
        if reason:
            return None, reason
        mapped = self.variable_for_initializer(node)
        if mapped is not None:
            variable, path, shape, reason = mapped
            nested_call = next((p for p in _parents(node) if p.type == 'call_expression'
                                and _contains(variable['value'], p)
                                and _contains(p.child_by_field_name('arguments'), node)), None)
            if nested_call is not None and variable['function'] is not None:
                return ('dynamic', None, None), self.cpp_call_problem(node)
            if reason:
                return None, reason
            if shape.get('unsafe'):
                return None, shape['unsafe']
            if self.attributes(variable['node']) and not variable['static']:
                return None, 'declaration_attributes'
            if shape['kind'] != 'pointer' or shape['pointee']['kind'] not in {'byte', 'void'}:
                return None, 'nonpointer_or_unknown_initializer_type'
            if variable['static']:
                reason = self.static_problem(variable)
                if reason:
                    return None, reason
                return ('static', variable, path), None
            reason = self.cpp_call_problem(node)
            return ('dynamic', None, None), reason
        if not any(p.type == 'function_definition' for p in _parents(node)):
            return None, 'unresolved_file_scope_constant_context'
        reason = self.cpp_call_problem(node)
        if reason:
            return None, reason
        if self.language == 'cpp':
            for parent in _parents(node):
                if parent.type == 'return_statement':
                    function = next((p for p in _parents(parent) if p.type == 'function_definition'), None)
                    declarator = function.child_by_field_name('declarator') if function is not None else None
                    shape = self.declared_type(function, declarator) if function is not None else _shape()
                    if (shape['kind'] != 'function' or shape['returns']['kind'] != 'pointer'
                            or shape['returns'].get('unsafe')):
                        return None, 'cpp_nonpointer_or_deduced_return'
                    break
        return ('dynamic', None, None), None

    def entry(self, value, kind='string', variable=None, element=None):
        if kind == 'string' and value in self.literal_entries:
            return self.literal_entries[value]
        index = len(self.entries)
        symbol = self.prefix + '_b_' + str(index)
        getter = self.prefix + '_get_' + str(index)
        entry = {'id': index, 'kind': kind, 'value': value,
                 'symbol': symbol if variable is None else variable['qualified'], 'getter': getter,
                 'element': element or 'char', 'variable': variable, 'occurrences': 0}
        self.entries.append(entry)
        if kind == 'string':
            self.literal_entries[value] = entry
        return entry

    def record_occurrence(self, node, entry, context):
        self.transformed_nodes.add((node.start_byte, node.end_byte))
        entry['occurrences'] += 1
        self.report['occurrences'].append(dict(self.location(node), entry_id=entry['id'],
                                               kind=entry['kind'], context=context))

    def add_static(self, variable, path, entry):
        key = variable['declarator'].id
        if key not in self.objects:
            self.objects[key] = {'variable': variable, 'slots': []}
        self.objects[key]['slots'].append((path, entry))

    def slot_cast(self, variable, path):
        shapes = [record[2] for record in self.initializer_map.values()
                  if record[0] is variable and record[1] == path and record[2]['kind'] == 'pointer']
        if not shapes:
            self.fail('unresolved_static_slot_type', variable['name'] + path)
        pointee = shapes[0]['pointee']
        return '(' + ('const ' if pointee['const'] else '') + pointee.get('spelling', 'void') + ' *)'

    def function_names(self):
        for node in self.nodes:
            if node.type != 'identifier' or self.text(node) not in {'__func__', '__FUNCTION__', '__PRETTY_FUNCTION__'}:
                continue
            function = next((p for p in _parents(node) if p.type == 'function_definition'), None)
            if function is None:
                continue
            name = _name_node(function.child_by_field_name('declarator'))
            value = self.text(name).encode('utf-8')
            if _marker_status(value) != 'target':
                continue
            self.literal_candidates += 1
            if self.language != 'c' or self.text(node) == '__PRETTY_FUNCTION__':
                self.skip(node, 'compiler_specific_function_name', 'function-name')
                continue
            reason = self.compiletime_reason(node)
            if reason:
                self.skip(node, reason, 'function-name')
                continue
            mapped = self.variable_for_initializer(node)
            if mapped is not None and mapped[0]['static']:
                self.skip(node, 'static_function_name_initializer', 'function-name')
                continue
            entry = self.entry(value + b'\0')
            self.edit(node.start_byte, node.end_byte, '((const char *) ' + entry['getter'] + '())')
            self.record_occurrence(node, entry, 'compiler-function-name')

    def literals(self):
        for node in self.nodes:
            if node.type not in LITERAL_TYPES or (node.parent is not None and node.parent.type == 'concatenated_string'):
                continue
            try:
                value = _literal_bytes(node, self.source)
            except Unsupported as error:
                if b'frida' in self.source[node.start_byte:node.end_byte].lower():
                    self.literal_candidates += 1
                    self.skip(node, str(error))
                continue
            status = _marker_status(value)
            if status is None:
                continue
            self.literal_candidates += 1
            if status == 'ordinary_friday':
                self.skip(node, status)
                continue
            context, reason = self.context(node)
            if reason:
                self.skip(node, reason)
                continue
            entry = self.entry(value + b'\0')
            if context[0] == 'static':
                variable, path = context[1:]
                self.edit(node.start_byte, node.end_byte, '(char *) ' + entry['symbol'])
                self.add_static(variable, path, entry)
                self.record_occurrence(node, entry, 'local-static' if variable['function'] is not None else 'file-static')
            else:
                replacement = entry['getter'] + '()'
                if self.language == 'c':
                    replacement = '((char *) ' + replacement + ')'
                self.edit(node.start_byte, node.end_byte, replacement)
                self.record_occurrence(node, entry, 'runtime-expression')

    def resolve_variable(self, node, name):
        scope = _scope(node)
        visible = [v for v in self.variables if v['name'] == name and v['name_node'].start_byte <= node.start_byte
                   and scope[:len(v['scope'])] == v['scope']]
        return max(visible, key=lambda v: (len(v['scope']), v['name_node'].start_byte)) if visible else None

    def numeric_bytes(self, variable):
        shape = variable['shape']
        if variable['function'] is not None or 'static' not in variable['storage']:
            raise Unsupported('resource_not_file_static')
        if shape['kind'] != 'array' or shape['element']['kind'] != 'byte' or not shape['element']['const']:
            raise Unsupported('resource_not_const_byte_array')
        if self.attributes(variable['node']):
            raise Unsupported('resource_storage_attributes')
        if shape.get('unsafe') or shape['element'].get('unsafe'):
            raise Unsupported('resource_type_attributes_or_unknown')
        value = variable['value']
        if value is None or value.type != 'initializer_list':
            raise Unsupported('resource_not_numeric_initializer')
        output = []
        for item in value.named_children:
            if item.type == 'comment':
                continue
            try:
                number = _integer(self.source[item.start_byte:item.end_byte])
            except (Unsupported, UnicodeError, ValueError):
                raw = self.source[item.start_byte:item.end_byte]
                if item.type == 'unary_expression' and raw.startswith(b'-'):
                    number = -_integer(raw[1:].strip())
                else:
                    raise Unsupported('resource_nonliteral_numeric_element')
            if number < -128 or number > 255:
                raise Unsupported('resource_numeric_element_out_of_byte_range')
            output.append(number & 255)
        count = shape['count']
        if shape['size_node'] is not None and count is None:
            raise Unsupported('resource_nonliteral_array_bound')
        if count is None:
            count = len(output)
        if count < len(output):
            raise Unsupported('resource_initializer_exceeds_bound')
        if count <= 0:
            raise Unsupported('resource_zero_length_array')
        return bytes(output) + b'\0' * (count - len(output))

    def resources(self):
        declaration_names = {v['name_node'].id for v in self.variables}
        for variable in self.variables:
            if not RESOURCE_NAME.fullmatch(variable['name']):
                continue
            self.resource_candidates += 1
            try:
                value = self.numeric_bytes(variable)
            except Unsupported as error:
                self.skip(variable['node'], str(error), 'numeric-resource', variable['name'])
                continue
            if variable['name'].encode('utf-8') in self.shadow.origins.symbols:
                self.skip(variable['node'], 'resource_reference_header_origin', 'numeric-resource', variable['name'])
                continue
            hidden_reference = next((r for r in self.shadow.regions
                                     if r['kind'] in {'attribute', 'typeof', 'builtin-type', 'asm-declarator', 'template-destructor', 'anonymous-enum-base', 'anonymous-bitfield-type'}
                                     and any(t.kind == 'identifier' and t.value == variable['name'].encode('utf-8')
                                             for t in self.shadow.hidden_tokens(r))), None)
            if hidden_reference is not None:
                self.skip(variable['node'], 'resource_reference_hidden_compiler_context', 'numeric-resource', variable['name'])
                continue
            qualified_uses = [n for n in self.nodes if n.type == 'qualified_identifier'
                              and any(self.text(c) == variable['name'] for c in n.named_children)
                              and not _contains(variable['node'], n)]
            if qualified_uses:
                self.skip(variable['node'], 'qualified_resource_reference', 'numeric-resource', variable['name'])
                continue
            references = []
            unsafe = None
            for node in self.nodes:
                if node.type != 'identifier' or self.text(node) != variable['name'] or node.id in declaration_names:
                    continue
                if self.resolve_variable(node, variable['name']) is not variable:
                    continue
                if node.parent is not None and node.parent.type == 'qualified_identifier':
                    unsafe = 'qualified_resource_reference'
                    break
                if any(parent.type == 'enumerator' for parent in _parents(node)):
                    unsafe = 'resource_reference_enum_value_compile_time_context'
                    break
                if any(parent.type == 'bitfield_clause' for parent in _parents(node)):
                    unsafe = 'resource_reference_bitfield_width_compile_time_context'
                    break
                sizeof = next((p for p in _parents(node) if p.type in {'sizeof_expression', 'alignof_expression'}), None)
                if sizeof is not None:
                    value_node = sizeof.child_by_field_name('value') or sizeof.child_by_field_name('type')
                    while value_node is not None and value_node.type == 'parenthesized_expression':
                        value_node = next((c for c in value_node.named_children if c.type != 'comment'), None)
                    if value_node is None or value_node.id != node.id:
                        unsafe = 'resource_complex_sizeof_context'
                        break
                    references.append((node, ('sizeof', None, None)))
                    continue
                # A bare &array is a pointer-to-array, not a decayed byte pointer.
                ancestor = node.parent
                while ancestor is not None and ancestor.type == 'parenthesized_expression':
                    ancestor = ancestor.parent
                if ancestor is not None and ancestor.type == 'pointer_expression' and self.text(ancestor).lstrip().startswith('&'):
                    unsafe = 'address_of_resource_array'
                    break
                context, reason = self.context(node)
                if reason:
                    unsafe = 'resource_reference_' + reason
                    break
                references.append((node, context))
            if unsafe:
                self.skip(variable['node'], unsafe, 'numeric-resource', variable['name'])
                continue
            entry = self.entry(value, 'numeric-resource', variable, variable['shape']['element']['spelling'])
            encoded = self.encoded_initializer(value, entry['element'])
            self.edit(variable['value'].start_byte, variable['value'].end_byte, encoded)
            for node, context in references:
                if context[0] == 'sizeof':
                    self.report['occurrences'].append(dict(self.location(node), entry_id=entry['id'],
                                                           kind='numeric-resource', context='sizeof-preserved'))
                elif context[0] == 'static':
                    self.add_static(context[1], context[2], entry)
                    self.record_occurrence(node, entry, 'metadata-placeholder')
                else:
                    self.edit(node.start_byte, node.end_byte, entry['getter'] + '()')
                    self.record_occurrence(node, entry, 'runtime-typed-getter')
            self.resource_nodes.add(variable['declarator'].id)

    @staticmethod
    def encoded_initializer(value, element='unsigned char'):
        items = [('(%s) ' % element if element != 'unsigned char' else '') + '0x%02x' % (b ^ XOR_KEY) for b in value]
        lines = [', '.join(items[i:i + 24]) for i in range(0, len(items), 24)]
        return '{\n  ' + ',\n  '.join(lines) + '\n}'

    def patch_code(self, obj, index, local=False):
        variable = obj['variable']
        name = variable['name'] if local else variable['qualified']
        slots = obj['slots']
        count_name = self.prefix + '_patched_' + str(index)
        lines = ['unsigned int %s = 0;' % count_name]
        for path, entry in slots:
            slot = name + path
            lines.append('if ((const void *) (%s) == (const void *) (%s)) {' % (slot, entry['symbol']))
            lines.append('  %s = %s %s();' % (slot, self.slot_cast(variable, path), entry['getter']))
            lines.append('  ++%s;' % count_name)
            lines.append('}')
        lines.append('if (%s != %dU) __builtin_trap();' % (count_name, len(slots)))
        return '\n'.join(lines)

    def finalize_objects(self):
        global_objects = []
        for index, obj in enumerate(self.objects.values()):
            variable = obj['variable']
            paths = [p for p, _ in obj['slots']]
            if len(paths) != len(set(paths)):
                self.fail('duplicate_static_patch_slot', variable['name'], variable['node'])
            const_nodes, reason = self.removable_const(variable)
            if reason:
                self.fail(reason, variable['name'], variable['node'])
            for node in const_nodes:
                self.edit(node.start_byte, node.end_byte, '')
            if (self.language == 'cpp' and const_nodes and variable['function'] is None
                    and not ({'static', 'extern'} & variable['storage'])):
                self.edit(variable['node'].start_byte, variable['node'].start_byte, 'static ')
            local = variable['function'] is not None
            if local:
                once = self.prefix + '_object_once_' + str(index)
                code = ('\nstatic volatile gsize %s = 0;\n'
                        'if (g_once_init_enter (&%s)) {\n%s\n'
                        '  g_once_init_leave (&%s, 1);\n}\n') % (once, once, self.patch_code(obj, index, True), once)
                self.edit(variable['node'].end_byte, variable['node'].end_byte, code)
            else:
                global_objects.append((index, obj))
            self.report['static_objects'].append({
                'name': variable['qualified'] if not local else variable['name'],
                'scope': 'local-static' if local else 'file',
                'expected_slots': len(paths), 'paths': paths,
                'const_storage_removed': bool(const_nodes),
                'initialization': 'declaration-following-g_once' if local else 'constructor-101',
            })
        return global_objects

    def runtime(self, global_objects):
        prelude = []
        suffix = []
        for entry in self.entries:
            element = entry['element']
            getter = entry['getter']
            symbol = entry['symbol']
            index = entry['id']
            if entry['kind'] == 'string':
                prelude.append('static const unsigned char %s[] = %s;' % (symbol, self.encoded_initializer(entry['value'])))
            prelude.append('static const %s * %s (void);' % (element, getter))
            cache = self.prefix + '_cache_' + str(index)
            once = self.prefix + '_once_' + str(index)
            suffix.append('''static volatile gsize %(once)s = 0;
static %(element)s * %(cache)s;
static const %(element)s * %(getter)s (void)
{
  if (g_once_init_enter (&%(once)s)) {
    const volatile unsigned char * s = (const volatile unsigned char *) %(symbol)s;
    unsigned char * d = (unsigned char *) g_malloc (%(length)dU);
    gsize i;
    for (i = 0; i != %(length)dU; ++i) d[i] = (unsigned char) (s[i] ^ 0xa5U);
    %(cache)s = (%(element)s *) d;
    g_once_init_leave (&%(once)s, 1);
  }
  return %(cache)s;
}
''' % dict(once=once, element=element, cache=cache, getter=getter, symbol=symbol, length=len(entry['value'])))
        constructor = ['static void __attribute__ ((constructor (101))) %s_init (void)' % self.prefix, '{']
        for entry in self.entries:
            constructor.append('  (void) %s();' % entry['getter'])
        for index, obj in global_objects:
            constructor.append('  {\n' + self.patch_code(obj, index) + '\n  }')
        constructor.append('}')
        suffix.append('\n'.join(constructor))
        return ('\n'.join(prelude) + '\n').encode(), ('\n' + '\n'.join(suffix) + '\n').encode()

    def validate_packing(self, nodes):
        """Track pack state in source order, including physical opaque headers.

        A pragma affects aggregate definitions even when their static objects
        appear after a pop.  Those shapes remain unknown; ordinary byte/pointer
        objects and runtime expressions do not depend on member packing.
        """
        alignment, stack, cursor = None, [], 0
        events = []
        for node in sorted(nodes, key=lambda n: n.start_byte):
            parsed = _packing_directive(self.source[node.start_byte:node.end_byte])
            if parsed is None:
                self.fail('unsupported_pragma_pack', self.text(node)[:120], node)
            if alignment is not None and cursor < node.start_byte:
                self.packing_ranges.append((cursor, node.start_byte))
            action, label, value = parsed['action'], parsed['label'], parsed['alignment']
            if action == 'push':
                stack.append((label, alignment))
                if value is not None:
                    alignment = value
            elif action == 'pop':
                index = len(stack) - 1
                if label is not None:
                    index = next((i for i in range(len(stack) - 1, -1, -1)
                                  if stack[i][0] == label), -1)
                if index < 0:
                    self.fail('pragma_pack_unmatched_pop', self.text(node)[:120], node)
                alignment = stack[index][1]
                del stack[index:]
            elif action == 'set':
                alignment = value
            else:
                alignment = None
            cursor = node.end_byte
            events.append(dict(self.location(node), **parsed,
                               effective_alignment=alignment, stack_depth=len(stack)))
        if alignment is not None and cursor < len(self.source):
            self.packing_ranges.append((cursor, len(self.source)))
        if events:
            self.report['pragma_pack'] = {
                'original_bytes_emitted': True,
                'aggregate_slots': 'skipped_when_definition_overlaps_active_pack',
                'events': events,
                'active_ranges': [{'start_byte': start, 'end_byte': end}
                                  for start, end in self.packing_ranges],
                'final_alignment': alignment,
                'remaining_stack_depth': len(stack),
            }

    def validate_input(self):
        if self.root.has_error:
            errors = [n for n in _walk_all(self.root) if n.type == 'ERROR' or n.is_missing]
            for node in errors[:20]:
                self.report['failures'].append(dict(self.location(node), reason='parse_error', detail=self.text(node)[:120],
                                                    context=self.source[max(0, node.start_byte - 160):node.end_byte + 160].decode('utf-8', errors='replace')[:440]))
            self.fail('input_does_not_parse')
        packing_nodes = []
        for node in self.nodes:
            if not node.type.startswith('preproc_') or node.type in {'preproc_directive', 'preproc_arg'}:
                continue
            raw = self.source[node.start_byte:node.end_byte]
            if node.type == 'preproc_call':
                if re.match(rb'^\s*#\s*(?:line\s+)?[0-9]+\s+"[^"\r\n]*"(?:\s+[0-9]+)*\s*$', raw):
                    continue
                # Literal pack pragmas are retained for the semantic compiler
                # and tracked separately so dependent aggregate slots stay
                # unknown.  Other layout/macro directives remain fail-closed.
                if _packing_directive(raw) is not None:
                    packing_nodes.append(node)
                    continue
                if re.fullmatch(rb'\s*#\s*pragma\s+(?:GCC|clang)\s+diagnostic\s+(?:push|pop|(?:ignored|warning|error)\s+"-W[A-Za-z0-9_=+.,-]+")\s*', raw):
                    continue
                if re.fullmatch(rb'\s*#\s*pragma\s+(?:GCC\s+system_header|clang\s+system_header|once)\s*', raw):
                    continue
            self.fail('input_not_fully_preprocessed', self.text(node)[:120], node)
        self.validate_packing(packing_nodes)
        # AST parsing is not a substitute for the build's semantic compiler gate.

    def run(self):
        self.validate_input()
        self.collect_types()
        self.collect_variables_and_functions()
        self.hidden_syntax()
        self.literals()
        self.function_names()
        self.resources()
        global_objects = self.finalize_objects()
        if self.entries:
            missing = [name for name in ('g_malloc', 'g_once_init_enter', 'g_once_init_leave') if name not in self.functions]
            if 'gsize' not in self.type_records:
                missing.append('gsize')
            if missing:
                self.fail('missing_existing_glib_declarations', ', '.join(missing))
        ordered = sorted(self.edits, key=lambda e: (e[0], e[1]))
        last_end = 0
        parts = []
        for start, end, replacement in ordered:
            if start < last_end:
                self.fail('overlapping_ast_edits', '%d:%d' % (start, end))
            parts.extend((self.source[last_end:start], replacement))
            last_end = end
        parts.append(self.source[last_end:])
        output = b''.join(parts)
        if self.entries:
            prelude, suffix = self.runtime(global_objects)
            if self.cpp_opaque_roots:
                output = _SYNTHETIC_ORIGIN + prelude + output + b'\n' + _SYNTHETIC_ORIGIN + suffix
            else:
                output = prelude + output + suffix
            try:
                generated = _ParserShadow(output, self.language, self.parser, self.cpp_opaque_roots)
            except Unsupported as error:
                self.fail('generated_source_header_boundary', str(error))
            if generated.tree.root_node.has_error:
                self.fail('generated_source_does_not_parse')
        self.report['entries'] = [{
            'id': e['id'], 'kind': e['kind'], 'byte_length': len(e['value']),
            'sha256': hashlib.sha256(e['value']).hexdigest(), 'getter': e['getter'],
            'placeholder': e['symbol'], 'occurrences': e['occurrences'],
            'initialization': 'heap-g_once-constructor-101', 'element_type': e['element'],
        } for e in self.entries]
        self.report['summary'] = {
            'literal_candidates': self.literal_candidates,
            'literal_occurrences_transformed': sum(o['kind'] == 'string' for o in self.report['occurrences']),
            'resource_candidates': self.resource_candidates,
            'resources_transformed': len(self.resource_nodes),
            'skipped': len(self.report['skipped']),
            'heap_buffers': len(self.entries),
            'static_objects': len(self.objects),
            'expected_pointer_patches': sum(o['expected_slots'] for o in self.report['static_objects']),
            'unsupported_marker_total': sum(s['kind'] != 'numeric-resource' and s['reason'] != 'ordinary_friday'
                                            for s in self.report['skipped']),
            'unsupported_resource_total': sum(s['kind'] == 'numeric-resource' for s in self.report['skipped']),
            'ordinary_friday_skipped': sum(s['reason'] == 'ordinary_friday' for s in self.report['skipped']),
            'unsupported_reason_counts': {reason: sum(s['reason'] == reason for s in self.report['skipped'])
                                          for reason in sorted({s['reason'] for s in self.report['skipped']
                                                               if s['reason'] != 'ordinary_friday'})},
        }
        self.report['output_sha256'] = hashlib.sha256(output).hexdigest()
        self.report['ok'] = True
        return output, self.report


def outline_source(source, language='c', filename='<input>', cpp_opaque_roots=()):
    if language not in {'c', 'cpp'}:
        raise ValueError('language must be c or cpp')
    if isinstance(source, str):
        source = source.encode('utf-8')
    if not isinstance(source, bytes):
        raise TypeError('source must be bytes or str')
    return Transformer(source, language, filename, cpp_opaque_roots).run()


def outline_file(input_path, output_path, report_path, language='c', cpp_opaque_roots=()):
    input_path, output_path, report_path = map(Path, (input_path, output_path, report_path))
    resolved = [p.resolve() for p in (input_path, output_path, report_path)]
    if len(set(resolved)) != 3:
        raise ValueError('input, output, and report paths must be distinct')
    try:
        output, report = outline_source(input_path.read_bytes(), language, str(input_path), cpp_opaque_roots)
    except OutlineError as error:
        report_path.write_text(json.dumps(error.report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        # A failed invocation must not leave a stale successful output to compile.
        if output_path.exists():
            output_path.unlink()
        raise
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    output_path.write_bytes(output)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', '--reportJSON', dest='report', required=True, type=Path)
    parser.add_argument('--language', choices=('c', 'cpp'), required=True)
    parser.add_argument('--cpp-opaque-root', action='append', default=[], type=Path,
                        help='Explicit external C++ header subtree for a balanced parser-only boundary')
    args = parser.parse_args(argv)
    try:
        report = outline_file(args.input, args.output, args.report, args.language, args.cpp_opaque_root)
    except (OutlineError, OSError, ValueError) as error:
        print('string outlining failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
