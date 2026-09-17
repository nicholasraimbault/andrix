# SPDX-License-Identifier: Apache-2.0
"""Ordering model checks only. No Android or kernel authority is simulated as proof."""
from pathlib import Path
import importlib.util
import itertools
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    'andrix_delegated_lifetime_model', ROOT/'tests/delegated-supervision/model.py')
MODEL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODEL
SPEC.loader.exec_module(MODEL)
Instance, Lifetime, ServiceSlot = MODEL.Instance, MODEL.Lifetime, MODEL.ServiceSlot
Population, Cleanup = MODEL.Population, MODEL.Cleanup


class DelegatedContractModelTests(unittest.TestCase):
    def ready(self, slot=None):
        slot = slot or ServiceSlot(1)
        life = slot.start()
        self.assertIsNotNone(life)
        ref = life.identity
        self.assertTrue(life.bind_root(ref))
        self.assertTrue(life.verify_profile(ref))
        self.assertTrue(life.activate(ref))
        return slot, life, ref

    def empty_stopped(self, life, ref):
        self.assertTrue(life.stop(ref))
        self.assertTrue(life.report_process_exit(ref))
        self.assertTrue(life.observe_population(ref, Population.EMPTY))

    def test_activation_needs_complete_owned_setup(self):
        life = Lifetime(Instance(1, 1));ref = life.identity
        self.assertFalse(life.activate(ref))
        self.assertTrue(life.bind_root(ref))
        self.assertFalse(life.activate(ref))
        self.assertTrue(life.begin_mutation(ref, 1))
        self.assertTrue(life.verify_profile(ref))
        self.assertFalse(life.activate(ref))
        self.assertTrue(life.finish_mutation(ref, 1))
        self.assertTrue(life.activate(ref))
        self.assertFalse(life.activate(ref))
        self.assertFalse(life.begin_mutation(ref, 1))

    def test_stop_before_late_creation_owns_cleanup_without_activation(self):
        slot = ServiceSlot(1);life = slot.start();ref = life.identity
        self.assertTrue(life.begin_mutation(ref, 8))
        self.assertTrue(life.stop(ref))
        self.assertFalse(life.begin_mutation(ref, 9))
        self.assertTrue(life.bind_root(ref))
        self.assertTrue(life.verify_profile(ref))
        self.assertTrue(life.finish_mutation(ref, 8))
        self.assertFalse(life.activate(ref))
        self.assertIsNone(slot.start())
        self.empty_stopped(life, ref)
        self.assertTrue(life.begin_reclaim(ref))
        self.assertTrue(life.reclaimed(ref))
        self.assertIsNotNone(slot.start())

    def test_empty_is_not_enough_with_outstanding_mutation(self):
        slot, life, ref = self.ready()
        self.assertTrue(life.begin_mutation(ref, 3))
        self.empty_stopped(life, ref)
        self.assertFalse(life.can_reclaim())
        self.assertFalse(life.begin_reclaim(ref))
        self.assertIsNone(slot.start())
        self.assertTrue(life.finish_mutation(ref, 3))
        self.assertFalse(life.finish_mutation(ref, 3))
        self.assertEqual(life.population, Population.UNKNOWN)
        self.assertFalse(life.begin_reclaim(ref))
        life.observe_population(ref, Population.EMPTY)
        self.assertTrue(life.begin_reclaim(ref))

    def test_unknown_and_live_population_never_complete_cleanup(self):
        slot, life, ref = self.ready()
        life.stop(ref);life.report_process_exit(ref)
        for value in [Population.UNKNOWN, Population.POPULATED]:
            life.observe_population(ref, value)
            self.assertFalse(life.begin_reclaim(ref))
            self.assertFalse(life.reclaimed(ref))
            self.assertIsNone(slot.start())
        life.observe_population(ref, Population.EMPTY)
        self.assertTrue(life.begin_reclaim(ref))
        self.assertTrue(life.mark_blocked(ref))
        life.observe_population(ref, Population.UNKNOWN)
        self.assertFalse(life.reclaimed(ref))
        self.assertIsNone(slot.start())

    def test_cleanup_interruption_keeps_ownership_and_restart_fence(self):
        slot, life, ref = self.ready()
        self.empty_stopped(life, ref)
        self.assertTrue(life.begin_reclaim(ref))
        self.assertTrue(life.mark_blocked(ref))
        self.assertTrue(life.root_bound and life.stop_latched)
        self.assertIsNone(slot.start())
        self.assertFalse(life.reclaimed(ref))
        self.assertTrue(life.begin_reclaim(ref))
        self.assertTrue(life.reclaimed(ref))
        fresh = slot.start()
        self.assertNotEqual(ref, fresh.identity)
        self.assertFalse(fresh.active)

    def test_old_reference_cannot_target_replacement(self):
        slot, old, old_ref = self.ready()
        self.empty_stopped(old, old_ref);old.begin_reclaim(old_ref);old.reclaimed(old_ref)
        fresh = slot.start();new_ref = fresh.identity
        fresh.bind_root(new_ref);fresh.verify_profile(new_ref);fresh.activate(new_ref)
        self.assertFalse(fresh.stop(old_ref))
        self.assertFalse(fresh.observe_population(old_ref, Population.EMPTY))
        self.assertFalse(fresh.finish_mutation(old_ref, 1))
        self.assertFalse(fresh.reclaimed(old_ref))
        self.assertTrue(fresh.active)
        self.assertTrue(old.stop(old_ref))
        self.assertTrue(fresh.active)
        self.assertFalse(fresh.stop(Instance(2, new_ref.generation)))

    def test_empty_before_stop_or_initial_process_retirement_is_stale(self):
        _, life, ref = self.ready()
        life.observe_population(ref, Population.EMPTY)
        life.stop(ref)
        self.assertEqual(life.population, Population.UNKNOWN)
        life.observe_population(ref, Population.EMPTY)
        life.report_process_exit(ref)
        self.assertEqual(life.population, Population.UNKNOWN)
        self.assertFalse(life.begin_reclaim(ref))
        life.observe_population(ref, Population.EMPTY)
        self.assertTrue(life.begin_reclaim(ref))

    def test_a_new_mutation_invalidates_prior_population(self):
        _, life, ref = self.ready()
        life.observe_population(ref, Population.EMPTY)
        self.assertTrue(life.begin_mutation(ref, 11))
        self.assertEqual(life.population, Population.UNKNOWN)
        life.observe_population(ref, Population.EMPTY)
        self.assertTrue(life.finish_mutation(ref, 11))
        self.assertEqual(life.population, Population.UNKNOWN)

    def test_population_requires_the_exact_captured_root(self):
        life = Lifetime(Instance(1, 1));ref = life.identity
        self.assertFalse(life.observe_population(ref, Population.EMPTY))
        self.assertEqual(life.population, Population.UNKNOWN)
        self.assertTrue(life.bind_root(ref))
        self.assertFalse(life.observe_population(Instance(1, 2), Population.EMPTY))
        self.assertEqual(life.population, Population.UNKNOWN)

    def test_initial_service_exit_prevents_future_activation(self):
        life = Lifetime(Instance(1, 1));ref = life.identity
        life.bind_root(ref);life.verify_profile(ref)
        self.assertTrue(life.report_process_exit(ref))
        self.assertTrue(life.process_exited and life.stop_latched)
        self.assertFalse(life.activate(ref))
        self.assertFalse(life.active)

    def test_initial_service_exit_ends_active_state(self):
        _, life, ref = self.ready()
        self.assertTrue(life.report_process_exit(ref))
        self.assertFalse(life.active)
        self.assertTrue(life.stop_latched)
        self.assertEqual(life.cleanup, Cleanup.STOPPING)

    def test_delayed_empty_from_before_mutation_closure_is_rejected(self):
        _, life, ref = self.ready()
        life.begin_mutation(ref, 1)
        life.stop(ref);life.report_process_exit(ref)
        old = life.begin_observation(ref)
        self.assertIsNotNone(old)
        life.finish_mutation(ref, 1)
        self.assertIsNone(life.begin_observation(ref))
        self.assertFalse(life.report_population(old, Population.EMPTY))
        self.assertEqual(life.population, Population.UNKNOWN)
        self.assertFalse(life.begin_reclaim(ref))
        self.assertTrue(life.observe_population(ref, Population.EMPTY))
        self.assertTrue(life.begin_reclaim(ref))

    def test_observation_started_before_stop_cannot_authorize_cleanup(self):
        _, life, ref = self.ready()
        old = life.begin_observation(ref)
        life.stop(ref);life.report_process_exit(ref)
        self.assertFalse(life.report_population(old, Population.EMPTY))
        self.assertFalse(life.begin_reclaim(ref))
        self.assertTrue(life.observe_population(ref, Population.EMPTY))
        self.assertTrue(life.begin_reclaim(ref))

    def test_duplicate_or_foreign_observation_cannot_consume_current_query(self):
        _, life, ref = self.ready()
        old = life.begin_observation(ref)
        self.assertTrue(life.report_population(old, Population.POPULATED))
        current = life.begin_observation(ref)
        self.assertNotEqual(old, current)
        self.assertFalse(life.report_population(old, Population.EMPTY))
        foreign = MODEL.Observation(Instance(2, ref.generation), current.boundary, current.sequence)
        self.assertFalse(life.report_population(foreign, Population.EMPTY))
        self.assertEqual(life.pending_observation, current)
        self.assertTrue(life.report_population(current, Population.POPULATED))

    def test_activation_and_stop_orderings_do_not_resurrect(self):
        for order in [('stop','activate'),('activate','stop')]:
            life = Lifetime(Instance(1, 1));ref = life.identity
            life.bind_root(ref);life.verify_profile(ref)
            answers = [getattr(life, operation)(ref) for operation in order]
            self.assertEqual(answers, [True, False] if order[0]=='stop' else [True, True])
            self.assertTrue(life.stop_latched)
            self.assertFalse(life.active)
            self.assertFalse(life.activate(ref))

    def test_kernel_probe_refuses_an_undelegated_caller(self):
        result = subprocess.run([sys.executable, '-I', '-B',
            str(ROOT/'tests/delegated-supervision/kernel_cleanup.py')],
            capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('owned proof delegation only', result.stderr)

    def test_retirement_invariants_over_sequential_event_interleavings(self):
        actions = ['bind_root','verify_profile','activate','stop','report_process_exit',
                   'empty','begin_reclaim','reclaimed']
        checked = 0
        for ordering in itertools.permutations(actions):
            life = Lifetime(Instance(1, 1));ref = life.identity
            for operation in ordering:
                if operation=='empty':life.observe_population(ref, Population.EMPTY)
                else:getattr(life, operation)(ref)
                if life.process_exited:
                    self.assertFalse(life.active)
                    self.assertTrue(life.stop_latched)
                if life.cleanup==Cleanup.RETIRED:
                    self.assertTrue(life.stop_latched and life.root_bound and life.process_exited)
                    self.assertEqual(life.population, Population.EMPTY)
                    self.assertFalse(life.pending_mutations or life.active)
            checked += 1
        self.assertEqual(checked, 40320)


if __name__ == '__main__':
    unittest.main()
