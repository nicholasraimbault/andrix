# SPDX-License-Identifier: Apache-2.0
"""The read and round loss addresses of the next campaign profile, and the fault schedule that a
version 3 admission binds by its SHA-256.

A loss address is (plan, attempt, operation, milestone, ordinal, occurrence). It is never a note a
caller sends: the broker derives every part from the request, its own retained history and the
stored records, and an admitted fault acts exactly at the address it names.

- A round loss's operation is ROUND_DONE, its ordinal 0. Its milestone is the one the broker
  verified the round reached, and its occurrence counts the ticket's recorded boundaries at that
  milestone, this one included. It acts once the boundary's checkpoint is durable.
- A read loss's operation is OBSERVE. Its milestone is the one whose state the stored ticket is in
  when it is read (lab_protocol.read_milestone), its ordinal selects one reader of the
  observation (READERS), and its occurrence counts the completed runs of that reader for the
  ticket at that milestone, this one included. It acts once that reader's raw child completed.

The schedule is one strict canonical side record (lab_evidence): its schema, profile and
installation, then every admitted fault. The crossing, host and point cells keep their version 1
and 2 keys and modes. Under a version 3 admission every fault comes from this schedule and nothing
else."""
import re

import lab_evidence
import lab_protocol as proto

SCHEMA = 'andrix-fault-schedule-v1'
SCHEDULE_KEYS = ('schema', 'profile', 'installation', 'faults')
# The readers of a ticket's observation, by ordinal: the six simple groups, the receipt read and
# the observation's health compositions.
READERS = ('boot', 'checkpoint', 'factory', 'active', 'sessions', 'users', 'receipts', 'health')
RECEIPTS, HEALTH = READERS.index('receipts'), READERS.index('health')
OPERATIONS = {'read': 'OBSERVE', 'round': 'ROUND_DONE'}
LOSS_KEYS = ('cell', 'on', 'plan', 'attempt', 'operation', 'milestone', 'ordinal', 'occurrence', 'mode')
CELL = re.compile(r'[a-z0-9][a-z0-9-]{0,63}')
MAX_FAULTS = 256
# The most occurrences an address may name: no ticket reaches a milestone more often in its rounds.
MAX_OCCURRENCE = 10_000


class ScheduleError(ValueError):
    """A fault schedule of no exact form."""


def parse(data, installation, profile):
    """The faults of one canonical schedule of this installation and profile, in order. Each loss
    is checked here for its own form; the broker checks the rest against its admission and
    history."""
    try:
        value = lab_evidence.parse(data)
    except lab_evidence.SideError as error:
        raise ScheduleError('the schedule is not one canonical side record: %s' % error) from error
    if set(value) != set(SCHEDULE_KEYS) or value['schema'] != SCHEMA:
        raise ScheduleError('a schedule of another schema')
    if value['profile'] != profile or value['installation'] != installation:
        raise ScheduleError('a schedule of another profile or installation')
    faults = value['faults']
    if not isinstance(faults, list) or len(faults) > MAX_FAULTS:
        raise ScheduleError('a schedule lists at most %d faults' % MAX_FAULTS)
    for fault in faults:
        if not isinstance(fault, dict) or not isinstance(fault.get('cell'), str) or not CELL.fullmatch(fault['cell']):
            raise ScheduleError('a fault names its cell in lower case')
        if fault.get('on') in OPERATIONS:
            loss(fault)
    return faults


def loss(fault):
    """A read or round loss of exact form: its whole address and the halt mode. A round loss
    names a milestone and ordinal 0; a read loss names a milestone some read can be at, and a
    reader of the observation."""
    if set(fault) != set(LOSS_KEYS) or fault['mode'] != 'halt':
        raise ScheduleError('a loss is its cell and whole address, halting')
    if fault['operation'] != OPERATIONS[fault['on']]:
        raise ScheduleError('a %s loss acts at %s' % (fault['on'], OPERATIONS[fault['on']]))
    if not isinstance(fault['plan'], str) or not re.fullmatch(r'[0-9a-f]{32}', fault['plan']) or \
            fault['plan'] == proto.ZERO_ID:
        raise ScheduleError('a loss names its plan')
    for name, high in (('attempt', (1 << 31) - 1), ('occurrence', MAX_OCCURRENCE)):
        if type(fault[name]) is not int or not 1 <= fault[name] <= high:
            raise ScheduleError('a loss names its %s' % name)
    if fault['milestone'] not in proto.MILESTONES:
        raise ScheduleError('a loss names one milestone of the fixed enum')
    if type(fault['ordinal']) is not int:
        raise ScheduleError('a loss names its ordinal')
    if fault['on'] == 'round':
        if fault['ordinal'] != 0:
            raise ScheduleError('a round loss has no reader')
        return
    if not 0 <= fault['ordinal'] < len(READERS):
        raise ScheduleError('a read loss selects one reader of the observation')
    if fault['milestone'] == 'HEALTH_WINDOW_ENTRY':
        raise ScheduleError('no read is at the window entry: a read in the window is its progress')
    if fault['ordinal'] == HEALTH and fault['milestone'] != 'HEALTH_WINDOW_PROGRESS':
        raise ScheduleError('health is read only in the window')


def address(fault):
    """A loss's address as a tuple, for duplicate refusal."""
    return (fault['plan'], fault['attempt'], fault['operation'], fault['milestone'], fault['ordinal'],
            fault['occurrence'])
