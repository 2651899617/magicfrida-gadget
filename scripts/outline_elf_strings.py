#!/usr/bin/env python3
"""AST-only outliner for already preprocessed C/C++ translation units.

Integration API: outline_source(source, language='c', filename='<input>') returns
(output_bytes, report).  OutlineError carries a failure report.  This does not
rename APIs, rewrite binaries, invoke a compiler, or infer safety from branding.
The emitted code needs the translation unit's existing GLib declarations, and
GNU C/C++ constructor, typeof, and trap support.  No includes/macros are emitted.
"""

import argparse
import copy
import hashlib
import importlib.metadata
import json
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
    result = dict(kind=kind, const=False, const_nodes=[], unsafe=None)
    result.update(kwargs)
    return result


class Transformer:
    def __init__(self, source, language, filename):
        self.source = source
        self.language = language
        self.filename = filename
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
        self.tree = self.parser.parse(source)
        self.root = self.tree.root_node
        self.nodes = list(_walk(self.root))

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

    def _lookup_type_record(self, node, name):
        scope = _scope(node)
        records = self.type_records.get(name, [])
        visible = [r for r in records if r['start'] <= node.start_byte
                   and scope[:len(r['scope'])] == r['scope']]
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
        return any(c.type in {'attribute_specifier', 'attribute_declaration', 'ms_declspec_modifier'}
                   for c in _walk(node))

    def base_type(self, node):
        if node is None:
            return _shape()
        if node.type in {'primitive_type', 'sized_type_specifier'}:
            name = ' '.join(self.text(node).split())
            if name in {'char', 'signed char', 'unsigned char'}:
                return _shape('byte', spelling=name)
            if name == 'void':
                return _shape('void', spelling='void')
            return _shape('scalar', spelling=name)
        if node.type == 'enum_specifier':
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
            self.type_cache[key] = result
            return result
        if node.type in {'struct_specifier', 'union_specifier', 'class_specifier'}:
            body = node.child_by_field_name('body')
            if body is None:
                name = node.child_by_field_name('name')
                record = self._lookup_type_record(node, self.text(name)) if name is not None else None
                return self.base_type(record['node']) if record is not None and record['node'] != node else _shape(unsafe='unresolved_aggregate_type')
            if node.type != 'struct_specifier':
                return _shape(unsafe='union_or_class_layout')
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
            result = self.qualifiers(node, _shape('pointer', pointee=base))
            return self.apply_declarator(result, child)
        if node.type in {'array_declarator', 'abstract_array_declarator'}:
            count = None
            size = node.child_by_field_name('size')
            if size is not None:
                try:
                    count = _integer(self.source[size.start_byte:size.end_byte])
                except (Unsupported, ValueError, UnicodeError):
                    pass
            return self.apply_declarator(_shape('array', element=base, count=count, size_node=size), child)
        if node.type in {'function_declarator', 'abstract_function_declarator'}:
            result = _shape('function', returns=base, parameters=node.child_by_field_name('parameters'))
            return self.apply_declarator(result, child)
        if node.type == 'parenthesized_declarator':
            child = next((c for c in node.named_children if c.type != 'attribute_specifier'), None)
            return self.apply_declarator(base, child)
        return _shape(unsafe='unsupported_declarator')

    def declared_type(self, declaration, declarator):
        base = self.qualifiers(declaration, self.base_type(declaration.child_by_field_name('type')))
        return self.apply_declarator(base, declarator)

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

    def static_problem(self, variable):
        node = variable['node']
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
        for parent in _parents(node):
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
            signatures = self.functions.get(callee, [])
            if not signatures or index is None:
                return 'unresolved_cpp_call_parameter'
            for declaration, signature in signatures:
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
                    if shape['kind'] != 'function' or shape['returns']['kind'] != 'pointer':
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

    def validate_input(self):
        if self.root.has_error:
            errors = [n for n in self.nodes if n.type == 'ERROR' or n.is_missing]
            for node in errors[:20]:
                self.report['failures'].append(dict(self.location(node), reason='parse_error', detail=self.text(node)[:120]))
            self.fail('input_does_not_parse')
        for node in self.nodes:
            if not node.type.startswith('preproc_') or node.type in {'preproc_directive', 'preproc_arg'}:
                continue
            raw = self.source[node.start_byte:node.end_byte]
            if node.type == 'preproc_call' and re.match(rb'^\s*#\s*(?:line\s+)?[0-9]+\s+"[^"\r\n]*"(?:\s+[0-9]+)*\s*$', raw):
                continue
            self.fail('input_not_fully_preprocessed', self.text(node)[:120], node)
        # AST parsing is not a substitute for the build's semantic compiler gate.

    def run(self):
        self.validate_input()
        self.collect_types()
        self.collect_variables_and_functions()
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
            output = prelude + output + suffix
            if self.parser.parse(output).root_node.has_error:
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


def outline_source(source, language='c', filename='<input>'):
    if language not in {'c', 'cpp'}:
        raise ValueError('language must be c or cpp')
    if isinstance(source, str):
        source = source.encode('utf-8')
    if not isinstance(source, bytes):
        raise TypeError('source must be bytes or str')
    return Transformer(source, language, filename).run()


def outline_file(input_path, output_path, report_path, language='c'):
    input_path, output_path, report_path = map(Path, (input_path, output_path, report_path))
    resolved = [p.resolve() for p in (input_path, output_path, report_path)]
    if len(set(resolved)) != 3:
        raise ValueError('input, output, and report paths must be distinct')
    try:
        output, report = outline_source(input_path.read_bytes(), language, str(input_path))
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
    args = parser.parse_args(argv)
    try:
        report = outline_file(args.input, args.output, args.report, args.language)
    except (OutlineError, OSError, ValueError) as error:
        print('string outlining failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
