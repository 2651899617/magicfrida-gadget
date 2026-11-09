#!/usr/bin/env python3
"""Reject disconnected, stale and byte-mismatched build consumption evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.util.spec_from_file_location('ci_backing_audit', ROOT / 'scripts/audit_elf_backing_ci.py')
audit = importlib.util.module_from_spec(loader)
loader.loader.exec_module(audit)


def member(name, data):
    header = (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
              + '644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode('ascii')
    return header + data + (b'\n' if len(data) & 1 else b'')


class EvidenceTests(unittest.TestCase):
    def test_archive_requires_exact_object_bytes_and_supports_long_names(self):
        obj = b'\x7fELF-gum-object'
        data = b'!<arch>\n' + member('//', b'gumelfmodule.c.o/\n') + member('/0', obj)
        self.assertEqual(audit.archive_members(data, obj), ['gumelfmodule.c.o'])
        with self.assertRaisesRegex(ValueError, 'object bytes absent'):
            audit.archive_members(data, obj + b'changed')
        with self.assertRaisesRegex(ValueError, 'regular ar'):
            audit.archive_members(b'!<thin>\n', obj)
        with self.assertRaisesRegex(ValueError, 'exceeds archive'):
            audit.archive_members(data[:-2], obj)

    def test_archive_supports_bsd_names_and_rejects_truncation(self):
        name, obj = b'very-long-gum-object.o', b'\x7fELF-object'
        data = b'!<arch>\n' + member('#1/' + str(len(name)), name + obj)
        self.assertEqual(audit.archive_members(data, obj), [name.decode()])
        with self.assertRaisesRegex(ValueError, 'truncated'):
            audit.archive_members(b'!<arch>\n' + b'broken', obj)

    def test_ninja_escapes_preserve_spaces_colons_and_literal_dollars(self):
        line = 'build path$ with$ space/file$:name.o: cc src$$name.c | header.h || order.h'
        left, right = audit.split_edge(line)
        self.assertEqual(audit.tokens(left), ['path with space/file:name.o'])
        self.assertEqual(audit.tokens(right), ['cc', 'src$name.c', '|', 'header.h', '||', 'order.h'])
        with self.assertRaisesRegex(ValueError, 'unsupported Ninja variable'):
            audit.tokens('$unresolved/file')

    def test_order_only_dependency_cannot_prove_link_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            build = root / 'build'
            build.mkdir()
            for name in ('source.c', 'gum.o', 'gum.a', 'agent.so'):
                (build / name).write_bytes(name.encode())
            (build / 'build.ninja').write_text(
                'build gum.o: cc source.c\nbuild gum.a: ar gum.o\n'
                'build agent.so: link gum.a || unrelated.h\n', encoding='utf-8')
            (build / '.ninja_log').write_text('# ninja log v5\n' + ''.join(
                '0\t1\t0\t' + name + '\tdeadbeef\n' for name in ('gum.o', 'gum.a', 'agent.so')), encoding='utf-8')
            graph = audit.Graph(build, audit.Inputs(root))
            chain = graph.chain(build / 'agent.so', build / 'gum.o')
            self.assertEqual(chain, [build / 'gum.o', build / 'gum.a', build / 'agent.so'])
            with self.assertRaisesRegex(ValueError, 'missing data dependency'):
                graph.chain(build / 'agent.so', build / 'unrelated.h')

    def test_graph_requires_execution_log_for_each_real_link_step(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            build = root / 'build'
            build.mkdir()
            for name in ('gum.o', 'agent.so'):
                (build / name).write_bytes(name.encode())
            (build / 'build.ninja').write_text('build agent.so: link gum.o\n', encoding='utf-8')
            (build / '.ninja_log').write_text('# ninja log v5\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'absent from execution log'):
                audit.Graph(build, audit.Inputs(root)).chain(build / 'agent.so', build / 'gum.o')

    def test_input_hash_recheck_rejects_drift_and_workspace_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / 'object.o'
            path.write_bytes(b'before')
            inputs = audit.Inputs(root)
            inputs.add(path)
            path.write_bytes(b'after')
            with self.assertRaisesRegex(ValueError, 'changed during audit'):
                inputs.add(path)
            with self.assertRaisesRegex(ValueError, 'outside cloud workspace'):
                inputs.add(root.parent / 'outside.o')

    def test_agent_binding_checks_linked_rewrite_input_and_embedded_output(self):
        rewritten = b'full-rewritten-agent'
        linked = {'agent_sha256': 'a' * 64, 'agent_size': 123}
        embedded = {'sha256': audit.sha(rewritten), 'extent': len(rewritten)}
        rewrite = {'before': {'sha256': 'a' * 64, 'size': 123},
                   'after': {'sha256': audit.sha(rewritten), 'size': len(rewritten)}}
        audit.bind_embedded_agent(linked, embedded, rewritten, rewrite, b'outer' + rewritten)
        with self.assertRaisesRegex(ValueError, 'rewrite input differs'):
            audit.bind_embedded_agent({**linked, 'agent_sha256': 'b' * 64}, embedded, rewritten, rewrite, rewritten)
        with self.assertRaisesRegex(ValueError, 'differs from rewritten resource'):
            audit.bind_embedded_agent(linked, {**embedded, 'sha256': 'c' * 64}, rewritten, rewrite, rewritten)
        with self.assertRaisesRegex(ValueError, 'lacks rewritten Agent'):
            audit.bind_embedded_agent(linked, embedded, rewritten, rewrite, b'unrelated-server')

    def test_workflow_audits_each_profile_before_next_mutation_or_upload(self):
        text = (ROOT / '.github/workflows/build.yml').read_text(encoding='utf-8')
        compatible = text.index('- name: Audit compatible ELF backing consumption')
        mutate = text.index('- name: Add explicit Zygisk initialization source feature')
        zygisk = text.index('- name: Audit Zygisk ELF backing consumption')
        publish = text.index('- name: Publish verified build artifacts only')
        self.assertLess(compatible, mutate)
        self.assertLess(zygisk, publish)
        self.assertEqual(text.count('scripts/audit_elf_backing_ci.py'), 2)
        self.assertIn('out/provenance/', text)
        self.assertIn('out/provenance/', text[text.index('- name: Keep provenance and failure logs'):])


if __name__ == '__main__':
    unittest.main()
