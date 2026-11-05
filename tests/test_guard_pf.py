"""Isolated unit tests: only strings and pure functions, no real PF/network calls."""

import unittest

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location('guard_pf', Path(__file__).with_name('guard_pf.py'))
pf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pf)


BASE = '''# Existing user comment must survive.
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
'''


class GuardPFTests(unittest.TestCase):
    def rejects_main(self, text):
        with self.assertRaises(pf.UnsupportedPFConfig):
            pf.prepare_pf_conf(text)

    def test_default_baseline_is_preserved(self):
        result = pf.prepare_pf_conf(BASE)
        self.assertEqual(result.replace(pf.GUARD_BLOCK, ''), BASE)
        self.assertLess(result.index(pf.GUARD_BLOCK), result.index('\nanchor "com.apple/*"\n'))
        pf.validate_pf_conf(result)

    def test_idempotent(self):
        result = pf.prepare_pf_conf(BASE)
        self.assertEqual(pf.prepare_pf_conf(result), result)

    def test_loopback_skip_only(self):
        source = 'set skip on lo0\n' + BASE
        self.assertEqual(pf.prepare_pf_conf(source).replace(pf.GUARD_BLOCK, ''), source)
        for target in ('en0', 'utun99', '{ lo0 en0 }', 'all'):
            with self.subTest(target=target):
                self.rejects_main(f'set skip on {target}\n' + BASE)

    def test_unknown_policy_is_not_guessed(self):
        for rule in ('pass out quick all', 'block all', 'include "/tmp/other"',
                     'anchor "another-vpn"', 'set state-policy floating'):
            with self.subTest(rule=rule):
                self.rejects_main(rule + '\n' + BASE)

    def test_duplicate_missing_or_reordered_apple_rules_rejected(self):
        self.rejects_main(BASE + 'anchor "com.apple/*"\n')
        self.rejects_main(BASE.replace('nat-anchor "com.apple/*"\n', ''))
        self.rejects_main(BASE.replace('nat-anchor', 'TMP').replace('rdr-anchor', 'nat-anchor').replace('TMP', 'rdr-anchor'))

    def test_unmanaged_guard_reference_rejected(self):
        self.rejects_main(BASE + f'anchor "{pf.ANCHOR_NAME}"\n')

    def test_bad_markers_and_edited_guard_rejected(self):
        result = pf.prepare_pf_conf(BASE)
        for damaged in (result.replace(pf.END, ''), result + pf.GUARD_BLOCK,
                        result.replace(pf.ANCHOR_FILE, '/tmp/untrusted'),
                        result.replace(pf.BEGIN, '# changed marker')):
            with self.subTest(damaged=damaged):
                self.rejects_main(damaged)

    def test_guard_after_apple_is_rejected(self):
        self.rejects_main(BASE + pf.GUARD_BLOCK)

    def test_comments_and_missing_final_newline_preserved(self):
        source = BASE.rstrip('\n').replace('nat-anchor "com.apple/*"', 'nat-anchor "com.apple/*" # user note')
        self.assertEqual(pf.prepare_pf_conf(source).replace(pf.GUARD_BLOCK, ''), source)

    def test_exact_anchor(self):
        text = pf.render_anchor()
        pf.validate_anchor(text)
        self.assertIn('on utun99 all no state', text)
        self.assertIn('user 0 keep state (if-bound)', text)
        self.assertTrue(text.endswith('block drop out quick all\n'))
        self.assertNotIn('user != 0', text)

    def test_widened_or_floating_anchor_rejected(self):
        original = pf.render_anchor()
        for damaged in (original.replace('utun99', 'en0'),
                        original.replace('on utun99 all no state', 'on utun99 all keep state (if-bound)'),
                        original.replace('keep state (if-bound)', 'keep state'),
                        original.replace('block drop out quick all', 'block drop out quick inet all'),
                        original.replace('user 0', 'user 501'),
                        original + 'pass out quick all\n'):
            with self.subTest(damaged=damaged):
                with self.assertRaises(pf.UnsupportedPFConfig):
                    pf.validate_anchor(damaged)

    def test_active_main_filter_order(self):
        active = f'scrub-anchor "com.apple/*" all\nanchor "{pf.ANCHOR_NAME}" all\nanchor "com.apple/*" all\n'
        pf.validate_runtime_main_filter(active)
        pf.validate_runtime_main_filter('anchor "com.apple/*" all\n', require_guard=False)
        for damaged in ('pass out quick all\n' + active,
                        active.replace(f'anchor "{pf.ANCHOR_NAME}" all\n', ''),
                        f'anchor "com.apple/*" all\nanchor "{pf.ANCHOR_NAME}" all\n'):
            with self.subTest(damaged=damaged):
                with self.assertRaises(pf.UnsupportedPFConfig):
                    pf.validate_runtime_main_filter(damaged)

    def test_normalized_apple_scrub_and_dummynet_display(self):
        filters = f'anchor "{pf.ANCHOR_NAME}" all\nanchor "com.apple/*" all\n'
        scrub = 'scrub-anchor "com.apple/*" all fragment reassemble\n'
        dummynet = 'dummynet-anchor "com.apple/*" all\n'
        for active in (scrub + dummynet + filters, scrub + filters + dummynet,
                       scrub + filters.replace('\nanchor "com.apple', '\n' + dummynet + 'anchor "com.apple')):
            with self.subTest(active=active):
                pf.validate_runtime_main_filter(active)
        pf.validate_runtime_main_filter(scrub + 'anchor "com.apple/*" all\n' + dummynet,
                                        require_guard=False)

    def test_runtime_normalization_does_not_accept_unknown_policy(self):
        filters = f'anchor "{pf.ANCHOR_NAME}" all\nanchor "com.apple/*" all\n'
        scrub = 'scrub-anchor "com.apple/*" all fragment reassemble\n'
        dummynet = 'dummynet-anchor "com.apple/*" all\n'
        for active in (scrub.replace('reassemble', 'crop') + filters,
                       scrub.replace('com.apple/*', '/*') + filters,
                       scrub + filters.replace('com.apple/*', '/*'),
                       dummynet.replace('com.apple/*', 'other/*') + filters,
                       scrub + filters + 'pass out quick all\n' + dummynet,
                       scrub + filters + scrub,
                       scrub + scrub + filters,
                       dummynet + filters + dummynet,
                       scrub + filters.replace(f'anchor "{pf.ANCHOR_NAME}" all\n', '') + dummynet):
            with self.subTest(active=active):
                with self.assertRaises(pf.UnsupportedPFConfig):
                    pf.validate_runtime_main_filter(active)


if __name__ == '__main__':
    unittest.main()
