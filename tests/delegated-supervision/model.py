# SPDX-License-Identifier: Apache-2.0
"""Draft service ordering model, not a supervisor or an authority oracle.

Tests supply facts. This does not implement/prove kernel containment, Android caller
identity, profile setup, CE authority, concurrent I/O or the wire protocol.
"""
from dataclasses import dataclass, field
from enum import Enum, auto


class Population(Enum):
    UNKNOWN = auto()
    POPULATED = auto()
    EMPTY = auto()


class Cleanup(Enum):
    NONE = auto()
    STOPPING = auto()
    RECLAIMING = auto()
    BLOCKED = auto()
    RETIRED = auto()


@dataclass(frozen=True)
class Instance:
    boot: int
    generation: int

    def __post_init__(self):
        if self.boot <= 0 or self.generation <= 0:
            raise ValueError('positive instance components required')


@dataclass(frozen=True)
class Observation:
    instance: Instance
    boundary: int
    sequence: int


@dataclass
class Lifetime:
    identity: Instance
    root_bound: bool = False
    profile_verified: bool = False
    active: bool = False
    stop_latched: bool = False
    # This is the initial managed SERVICE process, not an owner shell/work entry.
    process_exited: bool = False
    population: Population = Population.UNKNOWN
    cleanup: Cleanup = Cleanup.NONE
    pending_mutations: set[int] = field(default_factory=set)
    used_mutations: set[int] = field(default_factory=set)
    boundary: int = 0
    observation_sequence: int = 0
    pending_observation: Observation | None = None

    def changed_boundary(self):
        self.boundary += 1
        self.population = Population.UNKNOWN
        # Keep the query slot occupied until its result/cancellation is consumed.
        # Invalidation is not permission to spawn an unlimited replacement reader.

    def begin_mutation(self, ref, token):
        if (ref != self.identity or token <= 0 or token in self.used_mutations
                or self.stop_latched or self.cleanup != Cleanup.NONE):
            return False
        self.used_mutations.add(token)
        self.pending_mutations.add(token)
        self.changed_boundary()
        return True

    def finish_mutation(self, ref, token):
        if ref != self.identity or token not in self.pending_mutations:
            return False
        self.pending_mutations.remove(token)
        self.changed_boundary()
        return True

    def bind_root(self, ref):
        if ref != self.identity or self.root_bound or self.cleanup == Cleanup.RETIRED:
            return False
        # Late creation remains owned even after Stop, but cannot activate.
        self.root_bound = True
        self.changed_boundary()
        return True

    def verify_profile(self, ref):
        if ref != self.identity or self.cleanup == Cleanup.RETIRED:
            return False
        self.profile_verified = True
        return True

    def activate(self, ref):
        if (ref != self.identity or self.active or self.stop_latched or self.process_exited
                or not self.root_bound or not self.profile_verified
                or self.pending_mutations or self.cleanup != Cleanup.NONE):
            return False
        self.active = True
        return True

    def stop(self, ref):
        if ref != self.identity:
            return False
        if self.cleanup == Cleanup.RETIRED or self.stop_latched:
            return True
        self.stop_latched = True
        self.active = False
        self.changed_boundary()
        self.cleanup = Cleanup.STOPPING
        return True

    def report_process_exit(self, ref):
        if ref != self.identity or self.cleanup == Cleanup.RETIRED:
            return False
        if not self.process_exited:
            self.process_exited = True
            self.changed_boundary()
        self.stop(ref)
        return True

    def begin_observation(self, ref):
        if (ref != self.identity or not self.root_bound or self.pending_observation
                or self.cleanup in [Cleanup.RECLAIMING, Cleanup.RETIRED]):
            return None
        self.observation_sequence += 1
        ticket = Observation(ref, self.boundary, self.observation_sequence)
        self.pending_observation = ticket
        self.population = Population.UNKNOWN
        return ticket

    def report_population(self, ticket, population):
        if ticket is None or ticket != self.pending_observation:
            return False
        self.pending_observation = None
        if (ticket.instance != self.identity or ticket.boundary != self.boundary
                or self.cleanup == Cleanup.RETIRED or not isinstance(population, Population)):
            return False
        self.population = population
        return True

    def observe_population(self, ref, population):
        # Synchronous convenience for tests, with the same ticket checks.
        ticket = self.begin_observation(ref)
        return self.report_population(ticket, population)

    def can_reclaim(self):
        return (self.stop_latched and self.root_bound and self.process_exited
                and not self.pending_mutations and self.pending_observation is None
                and self.population == Population.EMPTY)

    def begin_reclaim(self, ref):
        if (ref != self.identity or self.cleanup not in [Cleanup.STOPPING, Cleanup.BLOCKED]
                or not self.can_reclaim()):
            return False
        self.cleanup = Cleanup.RECLAIMING
        return True

    def mark_blocked(self, ref):
        if (ref != self.identity or not self.stop_latched
                or self.cleanup == Cleanup.RETIRED):
            return False
        self.cleanup = Cleanup.BLOCKED
        return True

    def reclaimed(self, ref):
        if (ref != self.identity or self.cleanup != Cleanup.RECLAIMING
                or not self.can_reclaim()):
            return False
        # Exact-object removal is an authoritative supplied fact, not a failed read.
        self.cleanup = Cleanup.RETIRED
        return True


class ServiceSlot:
    """Model of one declared service's proposed replacement fence."""
    def __init__(self, boot):
        if boot <= 0:
            raise ValueError('positive boot identity required')
        self.boot = boot
        self.sequence = 0
        self.current = None

    def start(self):
        if self.current is not None and self.current.cleanup != Cleanup.RETIRED:
            return None
        self.sequence += 1
        self.current = Lifetime(Instance(self.boot, self.sequence))
        return self.current
