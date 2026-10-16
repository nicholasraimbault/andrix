#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guarded host qualification of complete original creation bindings and exact encoded byte
admission. No compiler or JVM starts unless an actual cgroup bounds this process to 2 GiB of
memory, no swap, 2 CPUs and 256 tasks, with core dumps disabled. Otherwise the run is NOT_RUN.
The comparisons R0 qualified at 24bfb6a against earlier revisions are archived: they read pinned
Git objects only, through one manifest that the history and counter admission runners share.
Source checks are pure Python. Not Android, crash, power loss, storage or activation evidence."""
from pathlib import Path
import argparse
import ast
import contextlib
import functools
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/proof'))
sys.path.insert(0, str(ROOT / 'scripts/proof/tests'))
import native_principal_pins as integration  # noqa: E402
import test_native_header_footprint as b0  # noqa: E402

GIB = 1 << 30
PLATFORM = 'owner/tests/platform/'
FRAMEWORK_DIR = 'owner/platform/framework/'
FRAMEWORK = ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
             'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')
STUB_DIRECTORIES = ('native_principal_stubs', 'native_principal_xml_stubs')
PREDICTIONS = ROOT / 'scripts/proof/native_creation_binding_predictions.json'
REVISIONS = {'c926': 'c9264e496777a81c2465ba3d1a0da91d3a4a8855',
             'd104': 'd104e15bae58a74dbba6e3c3325a93f216773667',
             '7845': '78456b352267dba916778b90d7c926c4e67ef888',
             '24bf': '24bfb6ad3c5c9630faca141a93d3531851e280b8'}
# Exact baseline inputs taken from Git objects. c9264e4 and d104e15 are archived baselines.
# 78456b3 is the last version 1 normal image, the rollback reader that the version 2 normal store
# supported. Once lifecycle records exist, B1's image is the rollback floor (FLOOR below), and
# 78456b3 and 24bfb6a are comparisons below it. The sources of 78456b3 equal the version 2 normal
# sources of 24bfb6a except for the boot literal, the store comments and the host facade default,
# and the rollback model runs them under Format.V1. 24bfb6a is the source of the qualified version
# 2 normal image and the revision of the archive below: every comparison that R0 qualified against
# the working tree now reads its Git objects instead.
ARCHIVE = '24bf'
BASELINE_SHA256 = {
    'c926': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '0488cf2e519bb09891dc8d0e87e606cc786895548bc0ec3609fc9613103b8c13',
        'NativeIdentityRecords': '36ef5e04b842b091e7af98de81b8ae67392729f333aeacb706a09c2b78580b16',
        'NativeIdentityStore': '92679c46989ab121ec274e9ddac340164aa55aba534c106aca23885bbc1cf991',
        'NativeIdentityPersistence': '4fd90c2546a9f99181a01b2ca074b63627b44c927ba6fd8e59c93c3ec3224665',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '1efa172c937b58c87db4d2f02e2601b3a4735d7ebf3a9435b4472de67d769869'},
    'd104': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '0488cf2e519bb09891dc8d0e87e606cc786895548bc0ec3609fc9613103b8c13',
        'NativeIdentityRecords': '36ef5e04b842b091e7af98de81b8ae67392729f333aeacb706a09c2b78580b16',
        'NativeIdentityStore': 'cb4d195f841491ec8a5e3a35888d2c06a7ab651673a22da8a68098ad51d4b721',
        'NativeIdentityPersistence': 'f20100402ca0284c009097c96d74213533d828d035ab1d83e1d4211c7ce919af',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '547078cd90a6b9b1cd2b6b872081ce3b8712a8bf49a6585b869e61cb9c656d69'},
    '7845': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '1fa50501728a66b676020c83fce44d5868686db37a6b5867498975ae4d57ceb4',
        'NativeIdentityRecords': '412c2271a9efabf9937375bd42f2e49c5e3fb4d09935a9e98d6e5805736a3009',
        'NativeIdentityStore': 'fa69ee859973504b9529c36d85551eda9c8cbe04ae285d89d5390603a6d45c23',
        'NativeIdentityPersistence': 'f2fd1a5e6d272f99bb06973700d885523c1dbff033731b4a02e969f8bfb29f54',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '2eaa6c9dae109f949fb23b553b92d8396d4d65c70b42caa83650821ba2b40669'},
    '24bf': {
        'NativePrincipalPins': '6dfdec9565b2b2295c60f2e38ecff4e57f55b7a13fa15ff9beb4b1911ed999bb',
        'NativePrincipalManager': '1fa50501728a66b676020c83fce44d5868686db37a6b5867498975ae4d57ceb4',
        'NativeIdentityRecords': '412c2271a9efabf9937375bd42f2e49c5e3fb4d09935a9e98d6e5805736a3009',
        'NativeIdentityStore': '183324ae3188717941cc614ceba0d68bd93fbc1d0d0be5e7c0cd80bf97a81138',
        'NativeIdentityPersistence': 'f2fd1a5e6d272f99bb06973700d885523c1dbff033731b4a02e969f8bfb29f54',
        'NativePrincipalRecovery': '08ed1d161a632362fd02912abfb2b927b6ad1ee18c78deab0fe0f9129711b88e',
        'Settings': '0b78a6518a21bf3a5a365705a85bde454a41448e561b0c7cdf7d07b287120806'},
}
# The version 1 reader of the layouts the current sources emit: target, baseline revision and
# host adapter. b1-v1 is the current sources under Format.V1. Those sources stop modelling 78456b3
# once B1 edits them, so this reader and its facade rollback check are legacy guards of the
# existing format reader.
READERS = (('b1-v1', None, None),)
LEGACY_ROLLBACK = ('b1-v1',)
# The archived version 1 readers of the layouts the pinned 24bfb6a emitter writes, each over
# pinned Git objects only: 24bf-v1, the 24bfb6a sources under Format.V1 and the archived twin of
# the R0 rollback reader model, archived c9264e4, and the pinned 78456b3 image under Format.V1.
ARCHIVED_READERS = (('24bf-v1', ARCHIVE, 'b1'), ('c926', 'c926', 'baseline'), ('7845', '7845', 'b1'))
# The targets that model the 78456b3 rollback reader, which the version 2 normal store supported,
# over the archived layouts.
ARCHIVED_ROLLBACK_READERS = ('24bf-v1', '7845')
# The emitted layouts that hold a version 2 header copy, predicted from the writer protocol: all
# 38 but the three seed-synced steps whose prior header copies are version 1, where only the
# staging seed is version 2. The rollback checks assert this count, so no layout leaves the copy
# branch unnoticed. The controls are read again under Format.V2, the previous format. The retirement
# layouts are the lifecycle emitter's.
ROLLBACK_COPY_LAYOUTS = 35
ROLLBACK_CONTROLS = ('final-published', 'final-reserved')


def rollback_names(prefix, layouts, controls):
    """The case names one rollback check prints: each layout, each control and the copy count."""
    return sorted(['%s / %s' % (prefix, name) for name in layouts] + ['%s / version 2 copy layouts' % prefix]
                  + ['%s control / %s' % (prefix, name) for name in controls])


def copy_layouts(layouts):
    """How many emitted layouts record a version 2 header copy as their kind."""
    return sum((layout / 'kind').read_text() == 'copy\n' for layout in sorted(layouts.iterdir()))
# The archived header footprint suite, unchanged, as it ran in the B0 qualification.
ORIGINAL_B0_SHA256 = {
    'NativeHeaderTestSupport': 'fd6c83fd41958f4902e19143ac0fbd53b54e8483f00e9c701ed853ccb1ada91b',
    'NativeIdentityHeaderFootprintTest': 'bab48f444eb8680dfbe523889f196308fdc30bc43f2cd86b303b3e61299e85c7',
    'NativeHeaderWriteFaultTest': 'fa2efc9d24f1131fa814fe141fc1c60ac656c8aaeb6dd4adf249dcb464c04610',
    'NativeHeaderWriteFaults': '874a3ff09f4a261295173d4cd35931b58b3b536a80088d063a224973b3c5b1cd'}

# ---------------------------------------------------------------- the 24bfb6a archive: pins and data
# R0 qualified the version 2 normal sources at 24bfb6a against earlier revisions and across
# products. B1 edits those sources, so each such comparison is archived. An archived comparison
# reads only pinned Git objects through pinned_bytes, assembles its inputs with the working tree
# closed, runs only archive code and takes its expectations from the frozen data here and the
# pinned 24bfb6a predictions. That code is the 24bfb6a helpers the archive copies, which tests
# compare with their Git objects, and the archive's own loader, assemblies, phases and checks. It
# calls no living function and is built from no living constant, so living code and the current
# sources change none of its inputs or results; only an edit of the archive itself does. The living
# lists and functions of this runner follow the current sources; the archived ones do not.
ARCHIVED_PLATFORM = 'owner/tests/platform/'
ARCHIVED_FRAMEWORK_DIR = 'owner/platform/framework/'
ARCHIVED_STUB_DIRECTORIES = ('native_principal_stubs', 'native_principal_xml_stubs')
ARCHIVED_FACADE = ARCHIVED_PLATFORM + 'native_principal_stubs/com/android/server/pm/Settings.java'
ARCHIVED_STORE = ARCHIVED_FRAMEWORK_DIR + 'NativeIdentityStore.java'
ARCHIVED_PATCH = 'patches/grapheneos-2026081300/native-principal-pins.patch'
ARCHIVED_PROFILE = 'patches/grapheneos-2026081300/native-principal-pins.json'
# The adapted Settings among the ten patch outputs.
ARCHIVED_SETTINGS = 'services/core/java/com/android/server/pm/Settings.java'
# The predictions of the three runners at 24bfb6a, by runner.
ARCHIVED_PREDICTIONS = {'binding': 'scripts/proof/native_creation_binding_predictions.json',
                        'history': 'scripts/proof/native_creation_history_predictions.json',
                        'counter': 'scripts/proof/native_counter_admission_predictions.json'}
ARCHIVED_PIN_GROUPS = (
    # Product fixtures and host stubs. The host Settings facade is pinned in BASELINE_SHA256, and the
    # XML stub android/util/Xml.java is never read.
    (ARCHIVED_PLATFORM, {
        'AppIdSettingMap.java.inc': 'ac0721c8c98e1efbe17b64358f29a30ae514ceddff51f48959bd6249b256e9f7',
        'ResilientAtomicFile.java.inc': 'b9b0a369d3519713d16de6bf7ec574bcad5ae6c8d3132121a6124b8b2f4d1130'}),
    (ARCHIVED_PLATFORM + 'native_principal_stubs/', {
        'android/content/pm/Signature.java': '194cccdf1a00bb85a3189525ba7a43f88f30e3361660e590e0908321b3b8d644',
        'android/content/pm/SigningDetails.java': '05e0e97105a55f69bde585f576cb04a59960ff999be3dd8a9fbaecfa02dedac2',
        'android/content/pm/UserInfo.java': 'ff81825584932dcb182fcb44d12b1f27f8d71f6e78baf4a14d2ad641956a64fe',
        'android/os/Process.java': 'ffe360d2de8e077132bb80a71d05695472221a5c794410b0bc2fe2f69ce0e2d1',
        'android/os/UserHandle.java': '51815d9cea6375a89e27287956b7eb33753d14c4613fb38b51ede61403d55149',
        'android/util/Log.java': '45dfc0e11053b0273901815c020112d8bd2e15a33bac059ba1a3f98cf2d5b056',
        'com/android/server/LocalServices.java': 'c0adc1f494840fcb58d1acb6ac1943e56d63147667d2a13647913939ccc82c10',
        'com/android/server/pm/PackageManagerService.java':
            'd3cc9ab333fbfbc5f291ae3606e1daca5f0eaa5a7b0630f6858042559e71a1c7',
        'com/android/server/pm/PackageManagerTracedLock.java':
            'd4f07b6fe6761da9228129c7c25d4002f543f99f92ca2047720441ff3c624d3c',
        'com/android/server/pm/PackageSetting.java': '594378379a1fc99415d901731b89d2cbae983557a9b620c240060c1011f5043b',
        'com/android/server/pm/SettingBase.java': 'c2389dc480ad1e713f5f3c15037c7b7388569c237a7ecda586e4bae29fc52232',
        'com/android/server/pm/UserManagerInternal.java':
            'e0a8b11a125c2684fdd7231fcf434ad88a73631abf03e982d833519fd93e2842',
        'com/android/server/pm/pkg/PackageUserStateInternal.java':
            'bd82da9aeffde182bce106847cfeeebcc02cbfb1de94474eb27e35f963fe0fc6',
        'com/android/server/utils/SnapshotCache.java':
            'b9775ad4dc2c3b9d9affe27be93cf2a097437307a077fa5b7fe10106d43e334c',
        'com/android/server/utils/WatchedArrayList.java':
            'b1a32b1ac8a4bffab749749be8800f030dde82c2ace07e53b5aa41a11e4523ec',
        'com/android/server/utils/WatchedSparseArray.java':
            '689d2bd1d6bd6fe112b5d0a9ebb75dd8573731441770e866ac1f0d516c3a172c',
        'com/android/server/utils/Watcher.java': '8fe7fe546e40f3d6561af8b897e02e20dc5a03548172d7dbefde6436db172912'}),
    (ARCHIVED_PLATFORM + 'native_principal_xml_stubs/', {
        'android/annotation/NonNull.java': '6ddc0b4d052155af25bb53e667a9af619e37627895d7f3931df37ce03ce2b40d',
        'android/annotation/Nullable.java': '240f7f85d753d961120cdab80dfc49d1af63a1dc11db0e68d5532c8407689822',
        'android/os/FileUtils.java': '9852208a316783e5a76141551181bd6ec1c6f41275e67f0c334ec7d6a39f5db2',
        'android/os/ParcelFileDescriptor.java': '2ca584995f00f3608884c7850db8bc0592fc66ffad9180fbb520ac9dc0bdfbce',
        'android/system/ErrnoException.java': '80e2fd2821ed73ad4c5239d174d55735f86e850195bed37be90aac12acfb7324',
        'android/system/Os.java': '6cb0f0e9bc7af27a872e1dc9d3076f4cba7100c3ed6d2a973de7508a6d673d24',
        'android/system/OsConstants.java': 'a8a42f40daafd3f3d3115c09ccdf4aaaad4c2d3c76d6093a19140b18cfe8d15d',
        'android/system/StructStat.java': '9c79371a592cdf8e19f4b76e4229445725430ad390e4ffca95bfd5845de2890c',
        'android/util/Log.java': '1179e9289ee751a66dfa1fc3167ccae3eb09d1bdffe0198150f2b91cd5ed6326',
        'android/util/Slog.java': 'd05edc6412193d1027a8051abbf5dc9df082bf8e04173c09e01de84584249754',
        'com/android/internal/annotations/VisibleForTesting.java':
            '5f0d808d0ce0185826a8a145fd2ec7735ae185ade8ac3298af2cb5c24550371b',
        'com/android/internal/util/XmlUtils.java': 'd02b0c70ede9298e475a8975c268622a7b48aefc504f3c1c64559b10ef3118e8',
        'com/android/modules/utils/TypedXmlPullParser.java':
            '74bb7ccb4e8ffbbc19f635ab9a6c3224ab1be238f812389a93cc1bf9e4940b7f',
        'com/android/modules/utils/TypedXmlSerializer.java':
            '67cc6ce0438d60ad059b20d7d62be32b17950d4ff495bf5d9640f7170ee8ca17',
        'com/android/server/security/FileIntegrity.java':
            '34850de514202aa02bbf8f3ccfd0e3e2c016f37d5c66a3703de65bc56c8a4a78',
        'libcore/io/IoUtils.java': 'd5c7d4e663fde5f3e0d5a1d666055af45b9d0e87183b9309a8a173c108be640b',
        'org/xmlpull/v1/XmlPullParser.java': 'ed18ef0bf4db43202e7720502738031223361592aca7bbb99e26fdb909fd6248',
        'org/xmlpull/v1/XmlPullParserException.java':
            'a89e65c01d99a7ae49f44532d717c746623c76705aff0ddd9a9177b5e0009068'}),
    # The header footprint suite and its adapters; the binding, history and rollback emitters, readers
    # and checks; the history harness template, body inputs and stubs; the probes and parity.
    (ARCHIVED_PLATFORM, {
        'NativeHeaderTestSupport.java': '8632e5257eeb24f0c0d23fd8fdfd4ee363d30bc4890093b7421c24e43aa71560',
        'NativeIdentityHeaderFootprintTest.java': 'ff5f0c391bba8f9964fd99604e06830fe5c15751ee0d0f41d2e67762590d8e37',
        'NativeHeaderWriteFaultTest.java': 'e3654696626760add9d318d1c81b57e602f6f453e2c8f814732a1677959284f2',
        'NativeHeaderWriteFaults.java': '874a3ff09f4a261295173d4cd35931b58b3b536a80088d063a224973b3c5b1cd',
        'native_header_api/b1/NativeHeaderApi.java': '781f7d345cdcdc4c7a28ae1cb89deb90f219093600d50906337aa7e4f24bda25',
        'native_header_api/baseline/NativeHeaderApi.java':
            'b7d06aa0c39345c78c1498306c2fb2f9f29c88de8042d69fcaf8fcba166cf07f',
        'NativeBindingTestSupport.java': '2426ad2e672f28b762444727c9c34b9987fe5db4d7a1927a6c1d74b7ba8c199d',
        'NativeHistoryTestSupport.java': '60a69f504b04af32e5f7176c8ae9e5f751722a83942cf008942c11f013f31ff1',
        'NativeCreationBindingLayouts.java': '847f3b76af27f46d95bfd75a028a80d9f95000bb27138d600062c44fa1af3572',
        'NativeCreationBindingReaderCheck.java': 'eacbcf7553e40dab52a1e44d4334ffbb00cf8194424f584450213c60f2e13c98',
        'NativeRollbackReaderCheck.java': 'a4b5ce9ef166b89ab25f3add091ba3195e59bbde18e8c3d3cd28183b03ab5485',
        'NativeCreationHistoryLayouts.java': '53ef4f2ebfa447aead96f0109b65f729924c5cb9da7ac0272d914e685c3e5377',
        'NativeRollbackSeedingCheck.java': '9ffb1672654b0decf331ad524efa04020d05d54875070fdc1feeb416ae99020d',
        'NativeHistoryHarness.java.in': '583ff5af55297856de88ac490884d21384d731a9b257a8fed833e53ae2363fff',
        'native_history_api/b2/body-inputs.java.inc':
            '59f847a99f67c56d1803d561e9c29914cbe02f28e876a0e1731d943fcb493f84',
        'native_history_api/baseline/body-inputs.java.inc':
            '766194ff495b6a8c96e2ae50ff025be7aeb0630083fc9850cc805104b378b23d',
        'native_history_stubs/com/android/server/pm/pkg/PackageStateInternal.java':
            '8810412ebb8dd0bdc504ab6aa4e64487f754a71f8415a382d82f900c8168a6e1',
        'BodyOriginRetirementProbe.java': '34bfaf2c5cb8b62df05bd84e770e4d42b157cc8ad9119ab6a2ee5dbb43ff6e04',
        'NativeHistoryParity.java': '7103ec4c85ae556252a56a054bfac1b883edb2e1d42d8f9f5c2d9b1d51fa7d50',
        'NativeCounterAdmissionTest.java': '118bf58be05501cfdccf2f7198e90aba75b4d1311e82622ce780d6a7adadd89d',
        'UnsupportedCounterProbe.java': '894bb4d16c4d7170ccba9e358a08bfb3c9f95946246d95868040f9d059d4a087',
        'StaleSlotCounterProbe.java': '5b222adecd6f4466a789b8f29fde4270481868a6a45f7c70ec1e9d9023c8b1b3',
        'NativeCreationBindingTest.java': '65903d580d768cdcecc952f34b0acab83deaec3508f3acd2f987be87a6847881'}),
    # The recovery fragments, which the history harness and the counter admission surface read.
    (ARCHIVED_PLATFORM + 'native_recovery_fragments/', {
        'identity.java.inc': 'c7ba56ef6f687453db5a1c4c4a21d6c95ce036bdd4cf9b3ed1d1bb0ee5dd21bc',
        'system-cleanup.java.inc': 'a3fe313963a15e2cd8b7f9d5707ae89f53f470525343ff446e3904e06e72207c',
        'parse-failure.java.inc': 'f769bea3670ac3611d112b1b771b9d26abbb0ba5508a549dd746040e106214e6',
        'install-markers.java.inc': 'b0c2f79d9e02f99866ed50e832abb83913c90bab7ed7a13ace4aee1d5b279332',
        'system-delete.java.inc': '22f757c8cd48513a9003093561872b02d686f251e01ab2a08a97d8b3f2aa63c3',
        'path-safety.java.inc': 'c1db3fe3be384b360761c7953ffb12457fd8b10ecc16cdec6fcf73a99732bb6a',
        'restore-capacity.java.inc': '94f73c5bc31d28d85f51c678b60daa7eeaae3482e15840210895cb62f58ecdef',
        'admission.java.inc': 'f6fb1d4f8dd53dbb712f35f8832e51735657a4e5c1be948512c6d9f9b33fc8eb',
        'restore-history.java.inc': 'fabd0161b440933cd61d2234667bdeb72a5119a0b3c00eb0c9e61b30d316b444',
        'stored-history.java.inc': '08afa193e032e5eb3717a19584b90acaf81b1bb4541bd08cca298cc85dcf1b9a',
        'scan.java.inc': '369d036a9931ec07f0689f55717e7945d59d2da9a449360163d16df0591f719a',
        'recovery-seeding.java.inc': 'ddaed9137f94165c48c62528ead6a022005ff4f83296f11737a1cd9aba96de7b'}),
    # The native patch and its profile, which the candidate rebuild and the counter admission surface read.
    ('patches/grapheneos-2026081300/', {
        'native-principal-pins.patch': 'eeaf34b2101c58f36d577ec020feb64f30bbdc6ddb982d7647e09ff223f5d4d5',
        'native-principal-pins.json': '08a292503164e102e95688d757304de51b150fbafef64937ff0b16b18cfc3a08'}),
    # The predictions of the three runners as R0 qualified them: the archived expectations they state.
    ('scripts/proof/', {
        'native_creation_binding_predictions.json': '7ed0f8ca73b459ed3059150a65fb06278efddef673a0b9432f573c39b182fe56',
        'native_creation_history_predictions.json': 'bc3d0e9e64669a4fe2b531f07c6ff4567936d0e7a3de3b8425bbae2128bbf270',
        'native_counter_admission_predictions.json':
            '1eb32b8c5944c5dd46d03a58c1ea9dabd8824cec881d7d37f3942ceae762c573'}),
)
# Every input that an archived comparison of this runner, or of the history and counter admission
# runners, reads at 24bfb6a, by repository path, with the SHA-256 of its Git object. The framework
# sources and the host Settings facade of 24bfb6a are pinned in BASELINE_SHA256.
ARCHIVE_SHA256 = {directory + relative: digest for directory, group in ARCHIVED_PIN_GROUPS
                  for relative, digest in group.items()}
# The other pinned revisions supply the product fixtures and host stubs of 24bfb6a, except their
# facade, pinned in BASELINE_SHA256, and these.
PRODUCT_DIFFERENCES = {
    revision: {ARCHIVED_PLATFORM + 'native_principal_stubs/com/android/server/pm/PackageManagerService.java':
               '152bf506f9af9df0bd3bab46bd5a97d764d052bc02b855ffe8cd1b5beb2926ef'}
    for revision in ('c926', 'd104')}
# The other inputs that archived comparisons read at an older revision: here the original B0 suite
# of c9264e4. The history and counter admission runners add those of the revisions they register.
BASELINE_INPUTS_SHA256 = {'c926': {ARCHIVED_PLATFORM + name + '.java': digest
                                   for name, digest in ORIGINAL_B0_SHA256.items()}}
# The native helpers and the recovery fragments of 24bfb6a, by name.
ARCHIVED_FRAMEWORK = ('NativePrincipalPins', 'NativePrincipalManager', 'NativeIdentityRecords',
                      'NativeIdentityStore', 'NativeIdentityPersistence', 'NativePrincipalRecovery')
ARCHIVED_FRAGMENTS = {name: ARCHIVED_PLATFORM + 'native_recovery_fragments/' + name + '.java.inc' for name in (
    'identity', 'system-cleanup', 'parse-failure', 'install-markers', 'system-delete', 'path-safety',
    'restore-capacity', 'admission', 'restore-history', 'stored-history', 'scan', 'recovery-seeding')}
# The boot construction and format literals of 24bfb6a, by which the archived R0 checks compare.
ARCHIVED_CONSTRUCTION = ('        mNativeIdentityStore = new NativeIdentityStore(\n'
                         '                new File(Environment.getDataSystemDirectory(), "native-principals"),\n'
                         '                ')
ARCHIVED_PRODUCTION = 'NativeIdentityStore.Format.V2'
ARCHIVED_RETIRED = 'NativeIdentityStore.Format.V1'
# The frozen expectations of the archived runs, as the 24bfb6a runners and B0 module stated them.
ARCHIVED_STEPS = ('seed-synced', 'backup-renamed', 'backup-published', 'write-started', 'main-synced',
                  'reserve-synced', 'backup-unlink', 'backup-unlinked')
ARCHIVED_B0_TESTS = {'focused': ('NativeHeaderTestSupport', 'NativeIdentityHeaderFootprintTest'),
                     'faults': ('NativeHeaderTestSupport', 'NativeHeaderWriteFaultTest', 'NativeHeaderWriteFaults')}
ARCHIVED_B0_FOCUSED_NAMES = (
    "store repro / admission refuses reuse of B's creation ID",
    'store repro / reservation refused before any effect',
    'store repro / direct header write refused', 'store repro / selected header rewrite refused',
    'initializeNew refused', 'ensureFreshSlot refused', 'resumeCreatingDirectory refused',
    'publishCreatingSlot refused', 'confirmReleasedSlot cannot release an addition',
    'removeReleasingSlot refused',
    'CREATING to LIVE waits for reconciliation', 'LIVE to RELEASING waits for reconciliation',
    'unrelated final omission waits for reconciliation', 'owned retirement header steps refused',
    'exact original B retry', 'original plan with C id2', 'unpublished RETIRING B restated',
    'interrupted CREATING to LIVE is compatible', 'interrupted LIVE to RELEASING is compatible',
    'interrupted omission is compatible',
    'single intact main beside a torn reserve counts', 'single intact reserve beside a torn main counts',
    'disagreeing copies of one addition refuse', 'additions sharing a creation ID refuse',
    'B not substituted by another app ID', 'B not substituted by another creation ID',
    'B not substituted by another package',
    'addition of another lineage not reinterpreted', 'copy of another lineage refuses writes',
    'selected backup of another lineage refuses writes',
    'manager repro / reopened PMS issues nothing',
    'same manager / original B retry', 'same manager / C id2, C committed first',
    'same manager / C id2, B committed first', 'same manager / unpublished RETIRING B with C id2',
    'same manager / C issued first, both restated', 'same manager / B release waits for C',
    'reopened registry keeps holds and LIVE bindings',
    'predecessor of a protected reservation is compatible', 'dropped CREATING entry is no predecessor',
    'lower counter without a newer reservation refuses', 'higher counter only copy refuses header writes',
    'counter advances only with a pure reservation', 'mixed phase change and reservation write refuses',
    'mixed forward phase and addition copy needs its reservation first',
    'incompatible copy / LIVE addition', 'incompatible copy / addition at or below the counter',
    'incompatible copy / backward phase', 'incompatible copy / changed CREATING tuple',
    'incompatible copy / dropped LIVE entry', 'incompatible copy / skipped phase',
    'new entry in the observed range must be a known addition',
    'restatement must cover every copy counter')
ARCHIVED_B0_FAULT_NAMES = (
    'owned retry keeps B through a failure after startWrite',
    *('legacy owned retry / ' + step for step in ARCHIVED_STEPS),
    *('new reservation / ' + step for step in ARCHIVED_STEPS),
    'prior ordering / publication', 'prior ordering / release marker', 'prior ordering / omission',
    'prior ordering / confirmation', 'chained protected reservations',
    'legacy B with C id2 / C first', 'legacy B with C id2 / B first', 'unpublished RETIRING B',
    'interrupted publication then protected reservation',
    'foreign preferred backup is refused unchanged')
# The host fault seams that archived fault legs and emitters inject into pinned stores and strict
# writers: anchor, position, indentation, step and record file expression.
ARCHIVED_STORE_SEAMS = (
    ('        Node preferred = node(backup(main));\n', 'before', 8, 'backup-guard', 'main'),
    ('            out.getFD().sync();\n        }\n', 'after', 8, 'seed-synced', 'main'),
    ('                StandardCopyOption.REPLACE_EXISTING);\n', 'after', 8, 'backup-renamed', 'main'),
    ('        syncDirectory(main.getParentFile());\n', 'after', 8, 'backup-published', 'main'),
    ('            FileOutputStream out = atomic.startWrite();\n', 'after', 12, 'write-started', 'main'))
ARCHIVED_WRITER_SEAMS = (
    ('            finalizeStrict(mMainOutStream);\n', 'after', 12, 'main-synced', 'mFile'),
    ('            finalizeStrict(mReserveOutStream);\n', 'after', 12, 'reserve-synced', 'mFile'),
    ('            if (mTemporaryBackup.exists() && !mTemporaryBackup.delete()) {\n', 'before', 12,
     'backup-unlink', 'mFile'),
    ('            FileDescriptor directory = Os.open(mFile.getParent(),\n', 'before', 12,
     'backup-unlinked', 'mFile'))
ARCHIVED_LAYOUT_NAMES = tuple(sorted(
    [prefix + step for prefix in ('fresh-upgrade-', 'legacy-b-bound-c-', 'pending-retiring-',
                                  'restated-then-upgraded-', 'v2-publication-') for step in ARCHIVED_STEPS]
    + ['final-reserved', 'final-published', 'final-legacy-null', 'final-released']
    + ['bound-collision-' + kind for kind in ('package', 'principal', 'both')]))
ARCHIVED_COPY_LAYOUTS = 43
ARCHIVED_ROLLBACK_CONTROLS = ('final-published', 'final-reserved')

STEPS = b0.STEPS
FOCUSED_NAMES = (
    'plan / rows only for records of a valid snapshot', 'plan / signer sets are valid, bounded and copied',
    'V1 / a new entry without an owned row refuses before effects', 'V1 / held entries and additions need no row',
    "manager / another manager's unreserved pin refuses before issuance",
    'manager / a late preparation failure keeps the original issuance',
    'V1 / an owned flow writes the golden version 1 bytes', 'V2 / an owned flow writes the golden version 2 bytes',
    'V2 / legacy B beside new C writes the golden bytes', 'encoded length / equals every actual encoding',
    'encoded length / refuses what it cannot measure', 'admission / exactly MAX_BYTES is admitted and written',
    'admission / one byte over MAX_BYTES refuses before issuance', 'V2 / a restatement alone keeps version 1',
    'V2 / legacy B with new C upgrades, C committed first', 'V2 / legacy B with new C upgrades, B committed first',
    'V2 / a restatement stays version 1, then new C upgrades',
    'V2 / pending and unpublished RETIRING pins reserve together',
    'V2 / a held binding refuses another owned signer row', 'V2 / a bound addition is restated exactly or refused',
    'low level / the version 1 format never writes version 2',
    'low level / a new entry under version 2 needs a complete binding',
    'low level / a restatement alone never upgrades', 'low level / relabels and downgrades refuse',
    'low level / a binding is never changed, dropped or filled',
    'low level / an unselected addition is restated exactly', 'low level / an upgrade needs a pure reservation',
    'cross version / a V2 target beside V1 predecessors restores only its counter',
    'cross version / a V1 selection beside a V2 copy is incompatible',
    'cross version / a V1 copy above the selected counter is incompatible',
    'cross version / a V1 copy at the selected counter is incompatible',
    'cross version / a V1 copy below a counter only advance is incompatible',
    'cross version / a V1 copy without the newer reservation is incompatible',
    'cross version / an interrupted V1 publication then a protected V2 reservation',
    'binding mismatch / disjoint signers', 'binding mismatch / serial', 'binding mismatch / signer subset',
    'binding mismatch / signer superset', 'binding mismatch / two users', 'binding mismatch / zero users',
    'binding mismatch / another user', 'binding mismatch / publication of another serial or signer set',
    'binding match / an active body is usable', 'binding match / a retiring body is usable',
    'binding / a published body stays usable beside a later reservation',
    *('binding conflict evidence / ' + name for name in (
        'package only collision', 'principal only collision', 'package and principal collision',
        'an unrelated sibling stays usable', 'a serial mismatch keeps package evidence',
        'a tombstone keeps package evidence', 'swapped app IDs keep package evidence',
        'unselected copies failing the binding beside a collision',
        'unselected copies failing the binding beside an unrelated sibling',
        'a matching binding keeps ordinary duplicates',
        'an ordinary conflict alone keeps N, a failed binding withdraws it',
        'version 1 reads bound collisions as c9264e4 does',
        'unselected slot copy keeps package evidence',
        'unselected slot copy keeps principal evidence',
        'matching binding ignores unselected package body',
        'matching binding ignores unselected principal body')),
    'restored R / unrelated N reserves beside it without a row',
    "restored R / a changed APK signer refuses only R's own rebind",
    'restored R / a mismatched body is a conflict that keeps its header',
    'signer mutation / Q reserves P with its original signers',
    'signer mutation / a durable P reservation does not strand Q',
    *('V2 gate / header version %d in %s' % (version, position) for version in (3, 65535)
      for position in ('store.bin', 'store.bin.reservecopy', 'store.bin-backup', 'store.bin-seed')),
    'V2 gate / malformed and damaged version 2 frames are damage',
    'V2 gate / version 2 slot frames are footprints under V1',
    'V2 gate / version 2 slot frames are footprints under V2',
    'V2 gate / initialization writes an empty version 1 header',
    'V2 / publication and a later reservation keep version 2, and the marker refuses',
    'V1 reader / version 2 layouts stay read only with every hold')
# The production twins of b1 focused. Each common case runs under the earlier formats it names, as
# above, then once more under Format.V3, the production format, as its own run printed right after
# it. Format.V3 reserves the same version 2 headers and writes the same version 1 bodies as
# Format.V2, so a twin asserts the same outcome of the same steps. Where the earlier run also
# asserts a lifecycle refusal, the twin runs only the common half: under Format.V3 that operation is
# the lifecycle runner's, and its case map names those cases. FOCUSED_NAMES stays the list of the
# earlier runs, which the lifecycle runner reads for their refusals. These cases have no twin, each
# for its reason: their outcome is specific to an earlier format, or they construct no store.
NO_TWIN = {
    'plan / rows only for records of a valid snapshot': 'constructs no store',
    'plan / signer sets are valid, bounded and copied': 'constructs no store',
    'V1 / a new entry without an owned row refuses before effects': 'golden version 1 bytes',
    'V1 / held entries and additions need no row': 'a version 1 header, which Format.V3 binds and upgrades',
    'V1 / an owned flow writes the golden version 1 bytes': 'golden version 1 bytes',
    'encoded length / equals every actual encoding': 'constructs no store',
    'encoded length / refuses what it cannot measure': 'constructs no store',
    'low level / the version 1 format never writes version 2': 'a Format.V1 rule',
    'binding conflict evidence / version 1 reads bound collisions as c9264e4 does': 'a Format.V1 read',
    'V2 gate / version 2 slot frames are footprints under V1': 'the slot ceiling of the earlier formats',
    'V2 gate / version 2 slot frames are footprints under V2': 'the slot ceiling of the earlier formats',
    'V1 reader / version 2 layouts stay read only with every hold': 'a Format.V1 read'}
# A twin is named with V3 in place of the earlier run's V2 prefix, or V3 before a name without one.
# This twin drops the half its name would claim.
TWIN_NAMES = {'V2 / publication and a later reservation keep version 2, and the marker refuses':
              'V3 / publication and a later reservation keep version 2'}


def production_twin(name):
    """The name of a common case's production twin."""
    if name in TWIN_NAMES:
        return TWIN_NAMES[name]
    if name.startswith(('V2 / ', 'V2 gate / ')):
        return 'V3' + name[2:]
    return 'V3 / ' + name


PRODUCTION_TWINS = tuple(production_twin(name) for name in FOCUSED_NAMES if name not in NO_TWIN)
# Every run that b1 focused prints, in order: each case, then its production twin.
FOCUSED_RUNS = tuple(run for name in FOCUSED_NAMES
                     for run in ((name,) if name in NO_TWIN else (name, production_twin(name))))
FAULT_NAMES = (
    *('fresh upgrade / ' + step for step in STEPS),
    *('legacy B with bound C / C first / ' + step for step in STEPS),
    *('legacy B with bound C / B first / ' + step for step in STEPS),
    *('version 1 restatement under version 2 / ' + step for step in STEPS),
    *('restatement then upgrade / ' + step for step in STEPS),
    *('pending and RETIRING together / ' + step for step in STEPS),
    'version 2 prior ordering / publication', 'version 2 release marker refused before any step',
    'version 2 omission refused before any step', 'version 2 prior ordering / confirmation',
    'V3 prior ordering / release marker', 'V3 prior ordering / omission',
    *('V3 retirement publication / ' + step for step in STEPS),
    'interrupted V1 publication then protected upgrade')
# The presence matrix's refusal rows, which a run under an earlier format prints after its format, V1
# or V2: each release step and the retiring flag refuse on their healthy layout, and each release flow
# that Format.V3 takes refuses there before any effect. A Format.V3 run has none of them.
PRESENCE_REFUSALS = (
    'header omission refused on its healthy layout', 'header released refused on its healthy layout',
    'slot removal refused on its healthy layout', 'retiring flag refused on its healthy layout',
    'read-only namespace / genuine absence refused before any effect',
    'read-only slot / removal refused before any effect',
    'genuine absence / RELEASING continuation refused before any effect',
    'genuine absence / owned retirement refused before any effect',
    'readable torn seed / RELEASING removal refused before any effect')
# The presence matrix's passing runs under each format: the earlier formats add the retiring flag row.
PRESENCE_PASSED = {'V1': 94, 'V2': 94, 'V3': 93}


def presence_problems(run, format_name):
    """Why a presence run under this format did not pass exactly as predicted, or None."""
    refusals = ['%s / %s' % (format_name, name) for name in PRESENCE_REFUSALS]
    if run['returncode'] or '%d passed, 0 failed' % PRESENCE_PASSED[format_name] not in run['stdout'] \
            or 'Unprivileged DAC refused' not in run['stdout']:
        return 'presence %s matrix' % format_name
    if format_name == 'V3':
        if any(name.startswith(('V1 / ', 'V2 / ', 'V3 / ')) for name in run['passed']):
            return 'presence V3 matrix runs a refusal row'
    elif not set(refusals) <= set(run['passed']):
        return 'presence %s refusal rows missing: %s' % (format_name, sorted(set(refusals) - set(run['passed'])))
    return None


# The production default check: the host facade's default format against explicit Format.V3 over
# representative stores. Every substantive suite passes its format explicitly, so only this check
# notices when the facade's default stops being the production format.
DEFAULT_TEST = 'NativeProductionDefaultTest'
DEFAULT_CASES = ('a missing store', 'a store the facade initializes', 'an eligible version 1 body',
                 'a suspended version 2 slot', 'a retiring version 2 slot', 'a damaged header beside a body',
                 'a damaged slot', 'a header of version 3', 'a slot of version 3 with its stable prefix',
                 'a bound reservation', 'a version 2 slot beside a bound reservation',
                 'a reservation and publication through the manager')
# What the check prints, in order: each store booted by the default and by explicit Format.V3, the
# default constructors themselves, then the discrimination controls of the earlier formats.
DEFAULT_NAMES = (tuple('default / ' + case for case in DEFAULT_CASES)
                 + ('default / the facade without arguments constructs Format.V3',
                    'control / Format.V2 reads differently exactly where version 2 slots are supported state',
                    'control / Format.V1 reads differently exactly where version 2 records are'))
# The stores whose facts each earlier format reads otherwise than Format.V3, as the controls assert.
# Each earlier format also dumps another schema for every store, since the slot ceiling selects it.
DEFAULT_DIFFERS = {'V2': ('a suspended version 2 slot', 'a retiring version 2 slot',
                          'a version 2 slot beside a bound reservation'),
                   'V1': ('a suspended version 2 slot', 'a retiring version 2 slot',
                          'a version 2 slot beside a bound reservation', 'a bound reservation',
                          'a reservation and publication through the manager')}
# The facade's default route, which the routing controls change to an earlier format.
DEFAULT_ROUTE = '    Settings(Path existing, boolean initialize) { this(existing, initialize, %s); }\n'


def default_facade(format_name):
    """The host facade with its default routed to an earlier format, and nothing else changed."""
    return replace_once((ROOT / FACADE).read_text(), DEFAULT_ROUTE % PRODUCTION,
                        DEFAULT_ROUTE % ('NativeIdentityStore.Format.' + format_name))


def default_failures():
    """What the check fails with the facade's default routed to an earlier format: every default
    case, since each dumps another schema, and the default constructors' own case. The controls
    compare explicit formats alone, so they pass, as every explicitly formatted suite does."""
    return tuple(name for name in DEFAULT_NAMES if name.startswith('default / '))


def production_default_step(work, format_name=None):
    """The production default check over the current sources, with the facade's default routed to
    this earlier format when one is named, as an outcome against DEFAULT_NAMES."""
    files = {**product_sources(), **test_sources(['NativeHeaderTestSupport', 'NativeBindingTestSupport',
                                                  DEFAULT_TEST])}
    if format_name is not None:
        files['stubs/com/android/server/pm/Settings.java'] = default_facade(format_name).encode()
    return outcome(suite(work, files, DEFAULT_TEST), DEFAULT_NAMES)


LAYOUT_NAMES = tuple(sorted(
    [prefix + step for prefix in ('fresh-upgrade-', 'legacy-b-bound-c-', 'restated-then-upgraded-',
                                  'v2-publication-') for step in STEPS]
    + ['final-reserved', 'final-published', 'final-legacy-null']
    + ['bound-collision-' + kind for kind in ('package', 'principal', 'both')]))

# Every host run carries one label. production: Format.V3, the lifecycle format, as the normal
# image's one boot read constructs it, or code that constructs no store. A production run of a
# lifecycle writer or of the release engine is host evidence only: no production text calls either,
# and the image step requires both to stay out of the final DEX. previous: Format.V2 runs of the
# current sources, the format of the images from the version 2 normal store up to B1's, the rollback
# floor; they stay as regressions of the version 2 paths. They are no model of B1's image, which
# only its own sources, pinned from Git objects, can give: that is floor-model. legacy: Format.V1
# writes or Format.V1 end to end, which model no shipped reader since the normal image became
# version 2, and every Format.V1 read by the current sources, which stop modelling 78456b3 once B1
# edits them; they stay as regressions of the version 1 paths, and none is retired.
# rollback-reader: an older image reading newer state as its pinned objects do, below the rollback
# floor once lifecycle records exist: Format.V1 reading version 2 state as 78456b3 does, the
# rollback reader that the version 2 normal store supported; the pinned 78456b3 image and its twin;
# the pinned 24bfb6a sources; and the pinned 24bfb6a image under its own production Format.V2
# reading version 2 slots; in runs over pinned products only. The lifecycle rollback check is the
# one working-tree class among them. floor-model: B1's image, the rollback floor, modelled from its
# own sources pinned from Git objects at its revision: its own lifecycle reader check under its
# boot format, Format.V2, compiled with its product, host facade and stubs, its history harness
# filled from its candidate Settings and its test supports, every input pinned by the floor
# manifest below and assembled sealed, none from the working tree or the 24bfb6a archive. The
# lifecycle guest check is the one working-tree class compiled with it.
# archived-baseline: every other archived run, over pinned Git objects of an earlier revision,
# compared as history, whose inputs and results no edit of the working tree changes.
RUN_LABELS = ('production', 'rollback-reader', 'archived-baseline', 'legacy', 'previous', 'floor-model')
# Living runs carry only the living labels, archived runs only the archived ones, and the floor
# model's runs only its own.
LIVING_RUN_LABELS = ('production', 'legacy', 'previous')
ARCHIVED_RUN_LABELS = ('rollback-reader', 'archived-baseline')
FLOOR_RUN_LABELS = ('floor-model',)
# Which harnesses run under each label: label, runner, the host classes it runs and which runs.
# A harness that runs cases under more than one format is listed once per label. A living row's
# classes are compiled from the working tree, an archived row's from pinned 24bfb6a objects, and a
# floor-model row's from the floor's pinned objects.
# The one exception is the history parity driver: the living parity compiles its pinned 24bfb6a
# object, and the history source checks hold the working-tree driver to those bytes. The exception the
# other way is the lifecycle rollback check: a working-tree source written against the API of 24bfb6a
# and 78456b3 only, compiled only with their pinned products, under the rollback-reader label. The
# floor's exception is the lifecycle guest check: a working-tree source written against the API that
# B1 and the current sources share, compiled under the floor-model label only with the floor's
# pinned compile set, which its runner checks byte for byte.
LIVING_ROLLBACK_CHECKS = ('NativeLifecycleRollbackCheck',)
LIVING_FLOOR_CHECKS = ('NativeLifecycleGuestCheck',)
HARNESS_LABELS = (
    ('production', 'scripts/proof/tests/test_native_identity_store.py', ('NativeIdentityRecordsTest',),
     'the record codec, which constructs no store'),
    ('legacy', 'scripts/proof/tests/test_native_identity_store.py',
     ('NativeIdentityStoreTest', 'NativeIdentityPresenceTest', 'NativeIdentityVersionGateTest',
      'NativeIdentityFutureFormatTest'),
     'Format.V1 stores, including the default version 1 presence matrix, and the Format.V1 reads of'
     ' intact version 2 and later header frames and of version 2 and later slot frames, with the stable'
     ' prefix evidence of slot frames above version 2'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleCodecTest',),
     'the lifecycle record codec, its stable prefix reader and its goldens against the independent'
     ' encoder, which construct no store'),
    ('previous', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReadTest',),
     'the Format.V2 reads of version 2 slots and later frames as negative evidence only, with the facade'
     ' identity predicate and the candidate seeding, and its version 2 slot write refusals'),
    ('legacy', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReadTest',),
     'the same reads and refusals under Format.V1'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReadTest',),
     'the Format.V3 reads of version 2 slots as positive state, the discrimination controls, and its'
     ' version 2 slot writes'),
    ('previous', 'scripts/proof/native_lifecycle_record.py', ('NativeIdentityDumpTest',),
     'the schema 2 diagnostic under Format.V2 in the facade and in the candidate Settings text, with its'
     ' deferred names, bounds and unavailable envelopes'),
    ('legacy', 'scripts/proof/native_lifecycle_record.py', ('NativeIdentityDumpTest',),
     'the same diagnostic under Format.V1'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeIdentityDumpTest',),
     'the schema 3 diagnostic under Format.V3, whose slot ceiling selects it'),
    ('previous', 'scripts/proof/native_lifecycle_record.py',
     ('NativeLifecycleStoreTest', 'NativeLifecycleTransactionTest'),
     'the Format.V2 refusals of every lifecycle store transition and transaction, disposition, Restore and the'
     ' release engine with its store primitives included, before any effect, and the version 1 marker and release'
     ' that still work there'),
    ('legacy', 'scripts/proof/native_lifecycle_record.py',
     ('NativeLifecycleStoreTest', 'NativeLifecycleTransactionTest'), 'the same refusals and controls under Format.V1'),
    ('production', 'scripts/proof/native_lifecycle_record.py',
     ('NativeLifecycleStoreTest', 'NativeLifecycleTransactionTest', 'NativeLifecycleFaultTest'),
     'the Format.V3 lifecycle store transitions and transactions, the boot facts, disposition in a retired boot,'
     ' Restore and the gated release engine with its continuation from durable state, their writer rules and'
     ' refusals, and the fault sweeps of every transaction at each writer step, as host code'
     ' with no production caller'),
    ('previous', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleSettingsTest',),
     'the Format.V2 seeding deferral of a version 1 retiring body and the absence of lifecycle boot facts, through'
     ' the facade and the history harness'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleSettingsTest',),
     'the Format.V3 seeding of retiring, retired and suspended accounts, the boot facts, the retired boot rule and'
     ' the release body in Settings, through the facade and the history harness, the release'
     ' body with no production caller'),
    ('previous', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleManagerTest',),
     'the Format.V2 refusals of every lifecycle operation of the manager before any effect, its closure and pin'
     ' change included'),
    ('legacy', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleManagerTest',),
     'the same refusals under Format.V1'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleManagerTest',),
     'the Format.V3 lifecycle operations of the manager, its suspension closure and every activation point\'s'
     ' suspension refusal, the operations with no production caller'),
    ('rollback-reader', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleRollbackCheck',),
     'the rollback models of 24bfb6a under Format.V2 and 78456b3 under Format.V1 over every lifecycle layout,'
     ' a working-tree check compiled only with their pinned products and their own harness texts'),
    ('previous', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReaderCheck',),
     'the Format.V2 reads of every lifecycle layout by the current sources: names protected, the'
     ' lost mapping unable to register afresh, and the sibling in CONFLICT; an earlier format'
     ' regression, not a model of B1\'s image built from its pinned sources'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReaderCheck',),
     'the Format.V3 reads of the same layouts as positive state, and the discrimination control'),
    ('floor-model', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleReaderCheck',),
     'B1\'s image, the rollback floor: its own reader check with its pinned compile set, under'
     ' Format.V2 over every lifecycle layout, names protected, the lost mapping unable to register'
     ' afresh and the sibling in CONFLICT, with its swap, cross-format and wrong model controls'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleGuestCheck', 'LabHistoryStore'),
     'the B2 guest inputs: the guest generator, which constructs no store, writes each layout, and the'
     ' guest check reads them all under Format.V3 against their exact predictions, with the swap and cross'
     ' controls'),
    ('floor-model', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleGuestCheck',),
     'B1\'s image over the B2 guest inputs: the guest check, the one working-tree class, with the'
     ' floor\'s pinned compile set under Format.V2 against the floor\'s exact predictions, with its swap'
     ' and cross controls, and under Format.V3 as the wrong model, which reads as the production reader'),
    ('production', 'scripts/proof/native_lifecycle_record.py', ('NativeLifecycleLayouts',),
     'the store layouts that the Format.V3 lifecycle writers leave, at each state and every writer step of each'
     ' transaction, with the values no writer of B1 writes and the companions, for the rollback models and'
     ' the readers, from writers with no production caller'),
    ('production', 'scripts/proof/tests/test_native_identity_persistence.py', ('NativePrincipalRecoveryTest',),
     'the recovery view, which constructs no store'),
    ('legacy', 'scripts/proof/tests/test_native_identity_persistence.py', ('NativeIdentityPersistenceTest',),
     'Format.V1 transactions'),
    ('previous', 'scripts/proof/tests/test_native_identity_persistence.py', ('NativeIdentityPersistenceTest',),
     'the Format.V2 twins of its version 1 refusals, over copies of the same version 1 states'),
    ('previous', 'scripts/proof/native_creation_binding.py', ('NativeIdentityPresenceTest',),
     'the presence and unavailable matrix under Format.V2, where the release steps and the retiring flag refuse'
     ' on their healthy layouts'),
    ('previous', 'scripts/proof/tests/test_native_identity_store.py', ('NativeIdentityVersionGateTest',),
     'the version gate\'s Format.V2 entry point: every lifecycle write refused on a healthy version 2 layout'),
    ('previous', 'scripts/proof/tests/test_native_identity_store.py',
     ('NativeIdentityStoreTest', 'NativeIdentityFutureFormatTest'),
     'the Format.V2 twins of their version 1 lifecycle write refusals, over the same version 1 states'),
    ('production', 'scripts/proof/native_creation_binding.py', ('NativeIdentityPresenceTest',),
     'the presence and unavailable matrix under Format.V3, with the release engine\'s omission and the'
     ' lifecycle retirement, which no production text calls'),
    ('production', 'scripts/proof/native_creation_binding.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingFaultTest'),
     'the V3 cases of the header footprint suites and the binding faults: the release header steps through the'
     ' release engine\'s primitives and the lifecycle retirement\'s publication, with no production'
     ' caller'),
    ('production', 'scripts/proof/native_creation_binding.py', ('NativeCreationBindingTest',),
     'the V3 twins of the common cases of b1 focused, each asserting its case\'s outcome under Format.V3'
     ' without the lifecycle refusals that its earlier run asserts, and the production mutants, which'
     ' only those twins catch'),
    ('production', 'scripts/proof/native_creation_binding.py', ('NativeProductionDefaultTest',),
     'the host facade\'s default against explicit Format.V3 over representative stores, and its routing'
     ' controls, which give the default an earlier format that only this check catches'),
    ('previous', 'scripts/proof/native_creation_binding.py', ('NativeProductionDefaultTest',),
     'the Format.V2 discrimination control of the production default check'),
    ('legacy', 'scripts/proof/native_creation_binding.py', ('NativeProductionDefaultTest',),
     'the Format.V1 discrimination control of the production default check'),
    ('production', 'scripts/proof/tests/test_native_header_footprint.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest'),
     'the V3 cases of the header footprint suites and their mutants'),
    ('production', 'scripts/proof/tests/test_native_identity_store.py',
     ('NativeIdentityFutureFormatTest', 'NativeIdentityVersionGateTest'),
     'the lifecycle entry points of the future format matrix and the version gate under Format.V3: the'
     ' lifecycle writers and the release engine\'s primitives beside later frames, with no'
     ' production caller'),
    ('production', 'scripts/proof/tests/test_native_principal_pins.py',
     ('NativePrincipalPinsTest', 'NativePrincipalAllocatorTest'), 'the core and allocator, with no store'),
    ('legacy', 'scripts/proof/tests/test_native_principal_pins.py',
     ('NativePrincipalManagerTest', 'NativePreparationAdmissionTest', 'NativePrincipalPersistenceTest'),
     'explicit Format.V1 facades, the XML pin codec that no image ships, and the last manager case: a'
     ' version 2 header copy read as a footprint by the Format.V1 facade'),
    ('previous', 'scripts/proof/tests/test_native_principal_pins.py',
     ('NativePrincipalManagerTest', 'NativePreparationAdmissionTest'),
     'the Format.V2 twins of their retirement refusals, reopened over copies of the same version 1 states'),
    ('legacy', 'scripts/proof/tests/test_native_preparation_faults.py',
     ('NativePreparationFaultTest', 'NativePreparationAdmissionTest'), 'explicit Format.V1 facades'),
    ('previous', 'scripts/proof/tests/test_native_preparation_faults.py', ('NativePreparationAdmissionTest',),
     'the Format.V2 twins of its retirement refusal, reopened over a copy of the same version 1 state'),
    ('production', 'scripts/proof/tests/test_native_recovery_boot.py', ('NativeRecoveryBootTest',),
     'the exact adapted boot fragments over constructed views, with no store'),
    ('legacy', 'scripts/proof/tests/test_native_header_footprint.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest'),
     'the current header fence suites with direct current APIs: Format.V1 stores and facades'),
    ('previous', 'scripts/proof/tests/test_native_header_footprint.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest'),
     'the Format.V2 twins of the B0 suite\'s refusals, over copies of its version 1 states'),
    ('archived-baseline', 'scripts/proof/native_creation_binding.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingLayouts',
      'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck'),
     'b0 c926, d104 and 24bf over pinned Git objects, archived and adapted, the 24bfb6a and 78456b3 store'
     ' classes, the pinned 24bfb6a layout emitter, the c926 reader of its layouts and the version 2'
     ' controls of the archived rollback checks'),
    ('legacy', 'scripts/proof/native_creation_binding.py',
     ('NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest', 'NativeCreationBindingTest',
      'NativeCreationBindingFaultTest', 'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck'),
     'current header fence suites on the current sources, the V1 writer and reader cases of b1 focused and its mutants, the'
     ' Format.V1 twins of the b1 retirement refusals, and the b1-v1 reader and facade rollback check of the'
     ' current layouts'),
    ('previous', 'scripts/proof/native_creation_binding.py',
     ('NativeCreationBindingTest', 'NativeCreationBindingFaultTest', 'NativeCreationBindingLayouts',
      'NativeRollbackReaderCheck', 'NativeIdentityHeaderFootprintTest', 'NativeHeaderWriteFaultTest'),
     'the V2 cases of b1 focused, the b1 fault matrix, the layout emitter, the B1 mutants, the'
     ' Format.V2 twins of the current header refusals and the version 2 controls of the b1-v1 facade rollback'
     ' check'),
    ('rollback-reader', 'scripts/proof/native_creation_binding.py',
     ('NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck'),
     'the pinned 24bf-v1 and 7845 readers of the archived layouts with their facade rollback checks'),
    ('previous', 'scripts/proof/native_creation_history.py',
     ('NativeCreationHistoryTest', 'NativeCreationHistoryFaultTest',
      'NativeHistoryParity', 'NativeCreationHistoryLayouts', 'NativeRollbackReaderCheck',
      'NativeRollbackSeedingCheck'),
     'the V2 cases and runs of b2 focused, b2 faults, the living parity against 24bfb6a'
     ' with the pinned driver, which the working-tree driver equals but for its format selection, the'
     ' emitter, the B2 mutants and the version 2 controls of the b2-v1 rollback checks'),
    ('production', 'scripts/proof/native_creation_history.py',
     ('NativeCreationHistoryTest', 'NativeCreationHistoryFaultTest', 'NativeHistoryParity'),
     'the V3 twins of the common cases of b2 focused and of the rebind sweeps of b2 faults, the production'
     ' parity of the working-tree driver under Format.V3 against the living Format.V2 outcomes with its'
     ' control, and the production mutants, which only those runs catch'),
    ('legacy', 'scripts/proof/native_creation_history.py',
     ('NativeCreationHistoryTest', 'NativeCreationHistoryFaultTest', 'NativeHistoryParity',
      'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck', 'NativeRollbackSeedingCheck'),
     'their Format.V1 cases over version 1 stores and their Format.V1 reads of version 2 layouts, the'
     ' Format.V1 twins of the b2 retirement refusals, the Format.V1 runs of the living parity with the'
     ' same pinned driver, and the b2-v1 reader and its facade and seeding rollback checks of the current'
     ' layouts'),
    ('rollback-reader', 'scripts/proof/native_creation_history.py',
     ('NativeHistoryParity', 'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck',
      'NativeRollbackSeedingCheck'),
     'the Format.V1 runs of the archived 24bfb6a parity side, and the pinned 24bf-v1 and 7845 readers of'
     ' the archived layouts with their facade and seeding rollback checks'),
    ('archived-baseline', 'scripts/proof/native_creation_history.py',
     ('BodyOriginRetirementProbe', 'NativeHistoryParity', 'NativeCreationHistoryLayouts',
      'NativeCreationBindingReaderCheck', 'NativeRollbackReaderCheck', 'NativeRollbackSeedingCheck'),
     'the 0018a1d and 24bfb6a probe sides, the 0018a1d parity side and the version 2 runs of the 24bfb6a'
     ' side, the pinned 24bfb6a emitter, the 0018 and c926 readers of its layouts and the version 2'
     ' controls of the archived rollback checks'),
    ('previous', 'scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest',),
     'the V2 cases of the focused suite and its mutants on the current sources'),
    ('legacy', 'scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest',),
     'the Format.V1 cases of the focused suite and its mutants on the current sources'),
    ('production', 'scripts/proof/native_counter_admission.py', ('NativeCounterAdmissionTest',),
     'the V3 twins of the common cases of the focused suite and its production mutant, which only those'
     ' twins catch'),
    ('rollback-reader', 'scripts/proof/native_counter_admission.py', ('NativeHistoryParity',),
     'the Format.V1 runs of the archived 24bfb6a parity side'),
    ('archived-baseline', 'scripts/proof/native_counter_admission.py',
     ('NativeCounterAdmissionTest', 'UnsupportedCounterProbe', 'StaleSlotCounterProbe', 'NativeHistoryParity'),
     'the 0018a1d, 89491b9 and 24bfb6a sides of the focused suite and their probes, the 89491b9 parity'
     ' side and the version 2 runs of the 24bfb6a parity side'),
    ('legacy', 'tests/native-identity/test_writer.py',
     ('NativePrincipalWriterFixtureTest', 'NativePrincipalWriterFixtureFaultTest',
      'NativePrincipalWriterFixtureTranscript'), 'the writer fixture tests on explicit Format.V1 facades'),
    ('production', 'scripts/proof/native_lab_history.py', ('NativeWriterLabRehearsal', 'LabHistoryStore'),
     'the lab rehearsal under Format.V3, and the generator and predictor, which construct no'
     ' store'),
    ('previous', 'scripts/proof/native_lab_history.py', ('LabHistoryStoreTest',),
     'the store fixture\'s Format.V2 reads of the generated store and of the predicted'
     ' reservation and body'),
    ('legacy', 'scripts/proof/native_lab_history.py', ('LabHistoryStoreTest',),
     'the store fixture\'s Format.V1 initialization and reads'),
    ('production', 'scripts/proof/native_lab_history.py', ('LabHistoryStoreTest',),
     'the store fixture\'s Format.V3 reads of the generated store, the reservation and the published body,'
     ' and its production control, which only those reads catch'),
)
# The labels of this runner's steps, by step or by the step's first two words, and of its readers.
STEP_LABELS = {'store classes': ('archived-baseline',),
               'b0 c926': ('archived-baseline',), 'b0 d104': ('archived-baseline',),
               'b0 24bf': ('archived-baseline',), 'current header': ('legacy', 'previous', 'production'),
               'b1 focused': ('previous', 'legacy', 'production'),
               'b1 faults': ('previous', 'legacy', 'production'),
               'presence v2': ('previous',), 'presence v3': ('production',),
               'production default': ('production', 'previous', 'legacy'),
               'readers': ('previous', 'legacy'),
               'rollback': ('legacy', 'previous'),
               'archived readers': ('archived-baseline', 'rollback-reader'),
               'archived rollback': ('rollback-reader', 'archived-baseline'),
               'mutants': ('previous', 'legacy', 'production')}
# This runner's archived steps. Every other step is living.
ARCHIVED_STEP_NAMES = ('store classes', 'b0 c926', 'b0 d104', 'b0 24bf', 'archived readers', 'archived rollback')
READER_LABELS = {'b1-v1': 'legacy', '24bf-v1': 'rollback-reader', 'c926': 'archived-baseline',
                 '7845': 'rollback-reader'}


def step_labels(step):
    """The labels of one of this runner's steps."""
    return STEP_LABELS[step] if step in STEP_LABELS else STEP_LABELS[step.rsplit(' ', 1)[0]]


def harness_class(name, archived=False, floor=False):
    """The one source of a labelled host class, or None: for a living row, its one host source under
    the platform tests or the native identity tests; for an archived row, its pinned 24bfb6a object;
    for a floor-model row, its object at the floor revision, pinned by the floor manifest."""
    if floor:
        pinned = FLOOR_PLATFORM + name + '.java'
        return '%s:%s' % (FLOOR, pinned) if pinned in FLOOR_SHA256 else None
    if archived:
        pinned = ARCHIVED_PLATFORM + name + '.java'
        return '%s:%s' % (REVISIONS[ARCHIVE], pinned) if pinned in ARCHIVE_SHA256 else None
    found = [path for path in (ROOT / PLATFORM / (name + '.java'), ROOT / PLATFORM / (name + '.java.in'))
             if path.is_file()]
    found += sorted((ROOT / 'tests/native-identity').rglob(name + '.java'))
    return found[0] if len(found) == 1 else None


def label_problems():
    """The labels name only known runners and host classes, use every label, and label every step
    and reader of this runner. A living row's classes are found in the working tree, an archived
    row's in the archive and a floor-model row's in the floor manifest. The living, archived and
    floor labels divide the labels between them. Living steps and readers carry only living labels
    and archived ones only archived labels; living readers read the current sources and archived
    readers a registered revision; the rollback reader models are archived rollback-reader targets,
    and the legacy rollback checks living legacy ones."""
    problems = []
    kinds = (LIVING_RUN_LABELS, ARCHIVED_RUN_LABELS, FLOOR_RUN_LABELS)
    if sorted(label for kind in kinds for label in kind) != sorted(RUN_LABELS):
        problems.append('the living, archived and floor labels do not divide the run labels')
    for label, runner, classes, runs in HARNESS_LABELS:
        if label not in RUN_LABELS or not (ROOT / runner).is_file() or not classes or not runs:
            problems.append('harness label row %s %s' % (label, runner))
        for name in classes:
            if harness_class(name, label in ARCHIVED_RUN_LABELS and name not in LIVING_ROLLBACK_CHECKS,
                             label in FLOOR_RUN_LABELS and name not in LIVING_FLOOR_CHECKS) is None:
                problems.append('labelled host class not found once: %s %s' % (label, name))
    if {row[0] for row in HARNESS_LABELS} != set(RUN_LABELS):
        problems.append('a run label names no harness')
    for step, labels in STEP_LABELS.items():
        allowed = ARCHIVED_RUN_LABELS if step in ARCHIVED_STEP_NAMES else LIVING_RUN_LABELS
        if not labels or not set(labels) <= set(allowed):
            problems.append('step %s carries labels %s' % (step, labels))
    if not set(ARCHIVED_STEP_NAMES) <= set(STEP_LABELS):
        problems.append('an archived step has no labels')
    readers = READERS + ARCHIVED_READERS
    if (set(READER_LABELS) != {target for target, _, _ in readers} or len(readers) != len(READER_LABELS)
            or any(baseline is not None or READER_LABELS.get(target) not in LIVING_RUN_LABELS
                   for target, baseline, _ in READERS)
            or any(baseline not in REVISIONS or READER_LABELS.get(target) not in ARCHIVED_RUN_LABELS
                   for target, baseline, _ in ARCHIVED_READERS)):
        problems.append('reader labels differ from the readers')
    if not set(ARCHIVED_ROLLBACK_READERS) <= {target for target, _, _ in ARCHIVED_READERS
                                     if READER_LABELS.get(target) == 'rollback-reader'}:
        problems.append('a rollback reader model is not an archived rollback-reader')
    if not set(LEGACY_ROLLBACK) <= {target for target, _, _ in READERS if READER_LABELS.get(target) == 'legacy'}:
        problems.append('a legacy rollback check is not a living legacy reader')
    return problems

STORE = FRAMEWORK_DIR + 'NativeIdentityStore.java'
PERSISTENCE = FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
MANAGER = FRAMEWORK_DIR + 'NativePrincipalManager.java'
# Deliberate B1 defects: source, exact replacements and the suites to run. The predictions file
# lists the checks each must fail.
MUTANTS = {
    'no-version-relaxation': (STORE, ((
        '        if (copy.version != selected.version && (copy.version != HEADER_V1\n'
        '                || selected.version != HEADER_V2 || copy.lastId >= selected.lastId)) return false;\n',
        '        if (copy.version != selected.version) return false;\n'),), ('focused', 'faults')),
    'permissive-v1-successor': (STORE, ((
        '                || selected.version != HEADER_V2 || copy.lastId >= selected.lastId)) return false;',
        '                || selected.version != HEADER_V2)) return false;'),), ('focused',)),
    'filling-legacy-b': (PERSISTENCE, ((
        '                entries.put(record.appId, known);\n',
        '                entries.put(record.appId, row == null || format.reservationVersion == VERSION_1\n'
        '                        ? known : new HeaderEntry(known.appId, SlotPhase.CREATING,\n'
        '                        known.creationId, known.creationPackage,\n'
        '                        new CreationBinding(record.userId, record.userSerial, row)));\n'),),
        ('focused', 'faults')),
    'upgrading-only-restatement': (PERSISTENCE, ((
        '        int version = bound ? format.reservationVersion : current.version;\n',
        '        int version = format.reservationVersion;\n'),), ('focused', 'faults')),
    'low-level-restatement-upgrade': (STORE, ((
        '        return next.version == selected.version || newlyBound;\n',
        '        return true;\n'),), ('focused',)),
    'wrong-version-measure': (PERSISTENCE, ((
        '                version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES) return null;',
        '                current.version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES)'
        ' return null;'),), ('focused', 'faults')),
    'no-byte-measure': (PERSISTENCE, ((
        '        if (list.size() > NativeIdentityRecords.MAX_SLOTS || NativeIdentityRecords.encodedHeaderLength(\n'
        '                version, current.lineage, lastId, list) > NativeIdentityRecords.MAX_BYTES) return null;\n',
        '        if (list.size() > NativeIdentityRecords.MAX_SLOTS) return null;\n'),), ('focused',)),
    'current-packagesetting-signers': (MANAGER, ((
        '                rows.put(record.id, issuance.selection.currentSignerSha256);\n',
        '                rows.put(record.id, signerDigests(issuance.selection.setting));\n'),), ('focused',)),
    'omit-retiring': (MANAGER, ((
        '            } else if (pin.issuance() instanceof Issuance issuance && issuance.owner == this) {\n',
        '            } else if (pin.phase() != NativePrincipalPins.Phase.RETIRING\n'
        '                    && pin.issuance() instanceof Issuance issuance && issuance.owner == this) {\n'),),
        ('focused', 'faults')),
    'withphase-downgrade': (PERSISTENCE, ((
        '            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);\n'
        '        }\n        return sameVersion(header, entries);\n',
        '            entries.add(entry.appId == appId ? new HeaderEntry(appId, phase, 0, "") : entry);\n'
        '        }\n        return new Header(header.lineage, header.lastId, entries);\n'),), ('focused', 'faults')),
    'new-incomplete-under-v2': (PERSISTENCE, ((
        '            CreationBinding binding = format.reservationVersion == VERSION_1 ? null\n'
        '                    : new CreationBinding(record.userId, record.userSerial, row);\n',
        '            CreationBinding binding = null;\n'),), ('focused', 'faults')),
    'low-level-incomplete-new': (STORE, ((
        '            if (format.reservationVersion > HEADER_V1 && (next.version != format.reservationVersion\n'
        '                    || entry.creationBinding == null)) return false;\n',
        ''),), ('focused',)),
    'rows-required-for-held': (PERSISTENCE, ((
        '                if (held.phase == SlotPhase.CREATING && !reservedFor(held, record, row)) return null;\n',
        '                if (row == null || (held.phase == SlotPhase.CREATING\n'
        '                        && !reservedFor(held, record, row))) return null;\n'),), ('focused',)),
    # The header footprint suite's app ID only defect. On these sources the projection reuses the
    # exact durable addition first, so that suite no longer reaches it; a direct writer case does.
    'compare-addition-app-id-only': (STORE, (
        ('            if (!addition.equals(headerEntry(next, addition.appId))) return false;',
         '            if (headerEntry(next, addition.appId) == null) return false;'),
        ('                    || entry.equals(copies.additions.get(entry.appId))) continue;',
         '                    || copies.additions.containsKey(entry.appId)) continue;')), ('focused',)),
    'binding-unchecked-on-load': (STORE, ((
        '                    if (index.phase == SlotPhase.CREATING && !bindingHolds(index, slot)) {\n'
        '                        bindingMismatch = true;\n'
        '                    }\n',
        ''),), ('focused',)),
    # A record whose complete creation binding fails stops being negative sibling evidence, so
    # the binding check makes a conflicting sibling usable again.
    'binding-conflict-first-copy-only': (STORE, ((
        '                for (Slot copy : entry.getValue().decodedCopies) {\n',
        '                for (Slot copy : entry.getValue().decodedCopies.subList(0,\n'
        '                        Math.min(1, entry.getValue().decodedCopies.size()))) {\n'),), ('focused',)),
    'binding-conflict-last-copy-only': (STORE, ((
        '                for (Slot copy : entry.getValue().decodedCopies) {\n',
        '                for (Slot copy : entry.getValue().decodedCopies.subList(\n'
        '                        Math.max(0, entry.getValue().decodedCopies.size() - 1),\n'
        '                        entry.getValue().decodedCopies.size())) {\n'),), ('focused',)),
    # Anchored to the one evidence predicate of the counter admission correction, which also
    # bounds creation. The defect is the same: a failed binding is no evidence.
    'binding-conflict-evidence-dropped': (STORE, ((
        '                        || entry.getValue().unavailable\n'
        '                        || bindingConflicts.contains(entry.getKey());',
        '                        || entry.getValue().unavailable;'),), ('focused',)),
    # Every CONFLICT record becomes evidence, so an ordinary unbound conflict alone withdraws a
    # sibling that version 1 keeps usable.
    'binding-conflict-evidence-every-conflict': (STORE, ((
        '                        || bindingConflicts.contains(entry.getKey());',
        '                        || entry.getValue().status == Status.CONFLICT;'),), ('focused',)),
    # The binding is checked only in the selected header copy, not in every decoded copy.
    'binding-checked-in-selected-header-only': (STORE, ((
        '                    if (index.phase == SlotPhase.CREATING && !bindingHolds(index, slot)) {\n',
        '                    if (copy == header.value && index.phase == SlotPhase.CREATING\n'
        '                            && !bindingHolds(index, slot)) {\n'),), ('focused',)),
    # A failed binding is evidence only when no ordinary conflict applies: the superseded rule.
    'binding-evidence-only-as-sole-cause': (STORE, ((
        '                if (bindingMismatch) bindingConflicts.add(entry.getKey());',
        '                if (bindingMismatch && !conflict) bindingConflicts.add(entry.getKey());'),),
        ('focused',)),
}
# The production format's line of the store's Format enum, and the production format regressions:
# each changes only that line, so every run under an earlier format must still pass and only the
# production twins may catch it. The format guard pins the enum, so these exist only as mutants.
PRODUCTION_ENUM = '        V3(2, 2, 2);\n'
PRODUCTION_MUTANTS = {
    # Format.V3 reserves version 1 headers again: a new entry carries no creation binding.
    'production-reservation-version-1': '        V3(2, 1, 2);\n',
    # Format.V3 reads version 2 headers as unsupported footprints.
    'production-header-ceiling-1': '        V3(1, 2, 2);\n',
    # Format.V3 reads intact version 3 headers as supported state, not as footprints.
    'production-header-ceiling-3': '        V3(3, 2, 2);\n'}
MUTANTS.update({name: (STORE, ((PRODUCTION_ENUM, line),), ('focused',))
                for name, line in PRODUCTION_MUTANTS.items()})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('creation binding source seam drift: ' + old[:80])
    return text.replace(old, new, 1)


def _limit(text):
    return None if text == 'max' else int(text)


def resource_guard(cgroup_root=Path('/sys/fs/cgroup'), membership=Path('/proc/self/cgroup')):
    """Require bounded memory, no swap, 2 CPUs, 256 tasks and disabled core dumps, from this
    process's cgroup or an ancestor. Nothing is created or changed. Returns None or a reason."""
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        return 'core dumps must be disabled with both limits zero'
    try:
        lines = membership.read_text().splitlines()
    except OSError as error:
        return 'cgroup membership unreadable: %s' % error
    unified = [line[3:] for line in lines if line.startswith('0::')]
    if len(unified) != 1 or not unified[0].startswith('/') or '..' in unified[0].split('/'):
        return 'no single unified cgroup membership'
    leaf = cgroup_root / unified[0].lstrip('/')
    chain = [leaf, *leaf.parents]
    if cgroup_root not in chain:
        return 'cgroup path outside the mounted hierarchy'
    chain = chain[:chain.index(cgroup_root) + 1]
    found = {'memory.max': [], 'memory.swap.max': [], 'pids.max': [], 'cpu.max': []}
    try:
        for directory in chain:
            for name, values in found.items():
                path = directory / name
                if not path.exists():
                    continue
                text = path.read_text().strip()
                if name == 'cpu.max':
                    quota, period = text.split()
                    if quota != 'max':
                        values.append(int(quota) / int(period))
                elif _limit(text) is not None:
                    values.append(_limit(text))
    except (OSError, ValueError) as error:
        return 'cgroup limits unreadable: %s' % error
    effective = {name: min(values) if values else None for name, values in found.items()}
    if (effective['memory.max'] is None or effective['memory.max'] > 2 * GIB
            or effective['memory.swap.max'] != 0
            or effective['cpu.max'] is None or effective['cpu.max'] > 2
            or effective['pids.max'] is None or effective['pids.max'] > 256):
        return 'required bounds absent: %s' % json.dumps(effective, sort_keys=True)
    return None


# ---------------------------------------------------------------- pure source checks

def java_digit16(unit):
    """Character.digit(unit, 16) for one UTF-16 code unit, as the compiler's unicode reader asks it:
    ASCII and fullwidth Latin hexadecimal letters and every Unicode decimal digit. A supplementary
    character is two code units in Java, neither of them a digit."""
    code = ord(unit)
    if code > 0xFFFF:
        return -1
    if 0x30 <= code <= 0x39:
        return code - 0x30
    if 0x41 <= code <= 0x46 or 0x61 <= code <= 0x66:
        return (code | 0x20) - 0x61 + 10
    if 0xFF21 <= code <= 0xFF26 or 0xFF41 <= code <= 0xFF46:
        return (code - 0xFF21 if code <= 0xFF26 else code - 0xFF41) + 10
    value = unicodedata.decimal(unit, -1)
    return value if 0 <= value <= 9 else -1


@functools.lru_cache(maxsize=4096)
def java_unicode_escapes(text):
    """The text as the compiler reads it, by the rules of javac's UnicodeReader: a backslash may
    begin an escape unless it follows a backslash that no escape produced; one or more u follow it,
    then four digits as Character.digit reads them. A broken escape, which javac refuses, raises
    ValueError."""
    out, position, end = [], 0, len(text)
    was_backslash = was_escape = False
    while position < end:
        unit = text[position]
        if unit == '\\' and (not was_backslash or was_escape):
            index = position + 1
            while index < end and text[index] == 'u':
                index += 1
            if index == position + 1:
                was_escape, was_backslash = False, not was_backslash
                out.append(unit)
                position += 1
                continue
            code = 0
            for _ in range(4):
                code = (code << 4) | (java_digit16(text[index]) if index < end else -1)
                if code < 0:
                    raise ValueError('a broken unicode escape at offset %d' % position)
                index += 1
            character = chr(code)
            was_escape, was_backslash = True, character == '\\' and not was_backslash
            out.append(character)
            position = index
        else:
            was_backslash = was_escape = False
            out.append(unit)
            position += 1
    return ''.join(out)


@functools.lru_cache(maxsize=4096)
def java_code_view(text, keep_literals=True):
    """Java text as code, in one lexical pass: comments blanked, a line comment ending at a CR or LF
    as in Java, and the contents of string, text block and character literals kept or blanked. A text
    block ends at the first triple quote that no backslash escapes. Lengths and line breaks are kept.
    Read text whose unicode escapes are translated."""
    out, at, end = [], 0, len(text)

    def blank(part):
        return re.sub(r'[^\r\n]', ' ', part)
    literal = (lambda part: part) if keep_literals else blank
    while at < end:
        if text.startswith('//', at):
            stop = at
            while stop < end and text[stop] not in '\r\n':
                stop += 1
            out.append(blank(text[at:stop]))
            at = stop
        elif text.startswith('/*', at):
            stop = text.find('*/', at + 2)
            stop = end if stop < 0 else stop + 2
            out.append(blank(text[at:stop]))
            at = stop
        elif text.startswith('"""', at):
            close = at + 3
            while close < end and not text.startswith('"""', close):
                close += 2 if text[close] == '\\' else 1
            close = min(close, end)
            out.append('"""' + literal(text[at + 3:close]))
            if close < end:
                out.append('"""')
            at = close + 3
        elif text[at] in '"\'':
            quote, scan = text[at], at + 1
            while scan < end and text[scan] not in (quote, '\r', '\n'):
                scan += 2 if text[scan] == '\\' else 1
            scan = min(scan, end)
            out.append(quote + literal(text[at + 1:scan]))
            if scan < end and text[scan] == quote:
                out.append(quote)
                scan += 1
            at = scan
        else:
            out.append(text[at])
            at += 1
    return ''.join(out)


# The identifier characters the guards read. Code outside comments and literals must be printable
# ASCII (java_code_outside_ascii), so these are exactly Java's identifier characters there, and a
# name compares exactly: no ignorable character can join it and no other letter can extend it.
JAVA_PART = r'[A-Za-z0-9_$\u0080-\U0010ffff]'
# Any other character could be part of a Java name, so it bounds no name: the guards never read
# finishRelease in a longer non ASCII name, and the ASCII rule refuses such code anyway.
BEFORE_NAME = r'(?<![A-Za-z0-9_$\u0080-\U0010ffff])'
AFTER_NAME = r'(?![A-Za-z0-9_$\u0080-\U0010ffff])'
# Explicit type arguments, nested ones included, which an invocation, a method or constructor
# reference and an instance creation may carry (JLS 15.9, 15.12, 15.13). A non-generic method or
# constructor ignores them, so they can stand before any name. Read in the structure view, where
# annotations are blank, so no parenthesis can occur inside them.
JAVA_TYPE_ARGUMENTS = r'<[^;(){}]*>'


def java_code_outside_ascii(text):
    """The characters of translated Java text, outside comments and literals, that are neither
    printable ASCII nor whitespace: none of the guarded sources has one."""
    return sorted({c for c in java_code_view(text, False) if not (' ' <= c <= '~' or c in '\t\n\r\f')})


_ANNOTATION_NAME = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*')


@functools.lru_cache(maxsize=4096)
def _annotations_blanked(view, whole):
    """A literal blanked view with each annotation blanked: whole, as @, its qualified name and its
    balanced argument list, or only its @ and qualified name, the argument list kept. Literal contents
    are already blank, so no parenthesis in data can unbalance it. @interface stays."""
    out = list(view)
    at, end = 0, len(view)
    while True:
        at = view.find('@', at)
        if at < 0:
            break
        index = at + 1
        while index < end and view[index] in ' \t\r\n\f':
            index += 1
        name = _ANNOTATION_NAME.match(view, index)
        if name is None or name.group(0) == 'interface':
            at += 1
            continue
        stop = name.end()
        if whole:
            after = stop
            while after < end and view[after] in ' \t\r\n\f':
                after += 1
            if after < end and view[after] == '(':
                depth, scan = 0, after
                while scan < end:
                    depth += {'(': 1, ')': -1}.get(view[scan], 0)
                    scan += 1
                    if depth == 0:
                        break
                if depth == 0:
                    stop = scan
        for index in range(at, stop):
            if out[index] not in '\r\n':
                out[index] = ' '
        at = stop
    return ''.join(out)


@functools.lru_cache(maxsize=4096)
def java_structure_view(text):
    """Translated Java text with comments, literal contents and annotations blanked, lengths and line
    breaks kept: the view the syntactic rules read. An annotation is @, its qualified name and its
    balanced argument list, nested annotations and array values included; literal contents are blank
    first, so no parenthesis in data can unbalance it. An annotation type declaration's @interface
    stays."""
    return _annotations_blanked(java_code_view(text, False), True)


def java_annotation_values(view):
    """A literal blanked view with each annotation's @ and qualified name blanked and its argument list
    kept, nested annotations' names blank too: annotation element values, such as class literals, stay
    readable while no annotation name reads as a call. Lengths and line breaks kept."""
    return _annotations_blanked(view, False)


def java_creation(name):
    """A pattern for an instance creation of the class with this simple name, in the structure view:
    new, any explicit type arguments and qualification, the name, any type arguments, then the
    argument list. It starts at new."""
    return ((BEFORE_NAME + r'new' + AFTER_NAME + r'\s*(?:%s\s*)?(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\.\s*)*' + BEFORE_NAME
             + r'%s\s*(?:%s\s*)?\(') % (JAVA_TYPE_ARGUMENTS, name, JAVA_TYPE_ARGUMENTS))


def java_constructor_reference(name):
    """A pattern for a constructor reference of the class with this simple name, type arguments
    included, in the structure view."""
    return BEFORE_NAME + r'%s\s*(?:%s\s*)?::\s*(?:%s\s*)?new' % (name, JAVA_TYPE_ARGUMENTS, JAVA_TYPE_ARGUMENTS) + AFTER_NAME


def java_class_literal(name):
    """A pattern for a class literal of the class with this simple name, arrays included."""
    return BEFORE_NAME + name + r'\s*(?:\[\s*\]\s*)*\.\s*class' + AFTER_NAME


def java_call_or_reference(name):
    """A pattern for a call of the method with this name, qualified or not and with any explicit type
    arguments, or a method reference to it. A declaration matches too; callers tell it apart."""
    return (r'(?:\.\s*(?:%s\s*)?|::\s*(?:%s\s*)?|(?<![A-Za-z0-9_$.:\u0080-\U0010ffff]))%s%s(?=\s*\()|::\s*(?:%s\s*)?%s%s'
            % (JAVA_TYPE_ARGUMENTS, JAVA_TYPE_ARGUMENTS, name, AFTER_NAME, JAVA_TYPE_ARGUMENTS, name, AFTER_NAME))


def living_views(text):
    """(kept, masked, structure) views of a living Java text after the compiler's escape translation;
    a text holding a broken escape is read untranslated, since it does not compile."""
    try:
        text = java_unicode_escapes(text)
    except ValueError:
        pass
    return java_code_view(text), java_code_view(text, False), java_structure_view(text)


def living_code(text):
    """A living guard's view of a Java text: unicode escapes translated as the compiler does, then
    comments blanked with literals kept. A text holding a broken escape is read untranslated; it does
    not compile, and the format guard refuses any escape in a production text."""
    try:
        text = java_unicode_escapes(text)
    except ValueError:
        pass
    return java_code_view(text)


def strip_java_comments(text):
    """Java text with comments blanked, string, text block and character literals kept: the living
    code view, java_code_view. Unicode escapes are read as written; living_code translates them."""
    return java_code_view(text)


def added_java(patch_text):
    """Added lines of the patch's Java file sections only."""
    lines, java = [], False
    for line in patch_text.splitlines():
        if line.startswith('+++ '):
            java = line.split()[1].endswith('.java')
        elif java and line.startswith('+'):
            lines.append(line[1:])
    return '\n'.join(lines)


# ---------------------------------------------------------------- the production format guard

# The production patch directory is the selected base's, patches/grapheneos-<release>/, whose
# patches the patch tools apply. The guard reads it as production, and the AOSP track of
# aosp_patches.py, which follows no GrapheneOS base. Every other patches/grapheneos-<release>/
# directory of a base recorded in upstream/bases is a candidate base's: production never reads it,
# and grapheneos_candidate.py checks it on its own with this guard, in a scratch checkout that
# selects that base. Anything else under patches/ is refused. Both production directories must
# exist, the AOSP track with the patch that its series record names by its file name there.
PRODUCTION_PATCHES = integration.BASE.patches.relative_to(ROOT).as_posix()
AOSP_TRACK = 'patches/android-17.0.0_r1'
AOSP_SERIES = AOSP_TRACK + '/series.json'
CANDIDATE_PATCHES = re.compile(r'grapheneos-([0-9]{10})')
# What a patch directory may hold, each a regular file: patches, their JSON records and a README.
PATCH_DIRECTORY_FILES = re.compile(r'[a-z0-9][a-z0-9-]*\.(?:patch|json)|README\.md')
# The production native patch and lab writer patch, in the production directory. The images of
# B1 and B2 keep their own paths, NATIVE_PATCH and NATIVE_PROFILE below.
PRODUCTION_NATIVE_PATCH = integration.PATCH.relative_to(ROOT).as_posix()
PRODUCTION_WRITER_PATCH = PRODUCTION_PATCHES + '/native-identity-writer.patch'
WRITER_FIXTURE = 'tests/native-identity/writer/NativePrincipalWriterFixture.java'
# The native helpers the native patch adds to the framework, by production text name.
NATIVE_HELPERS = tuple(path.relative_to(ROOT).as_posix() for path in integration.ADDED.values())
SETTINGS_SECTION = PRODUCTION_NATIVE_PATCH + ':' + integration.SETTINGS
FACADE = PLATFORM + 'native_principal_stubs/com/android/server/pm/Settings.java'
# The one boot construction of the adapted Settings, ported from the retired lab format tool:
# its method, the construction up to its format argument and the persistence that follows it.
METHOD = '    NativeIdentityStore.Loaded readNativeIdentityStoreForBoot() {\n'
CONSTRUCTION = ('        mNativeIdentityStore = new NativeIdentityStore(\n'
                '                new File(Environment.getDataSystemDirectory(), "native-principals"),\n'
                '                ')
BOOT_END = '        mNativeIdentityPersistence = new NativeIdentityPersistence(mNativeIdentityStore);\n'
# The format the boot construction passes: the lifecycle format, which reads version 2 slots as
# supported state. Production refuses the earlier formats: the previous one, which the images up to
# B1's, the rollback floor, pass, and the retired one of the images before the version 2 store.
PRODUCTION = 'NativeIdentityStore.Format.V3'
PREVIOUS = 'NativeIdentityStore.Format.V2'
RETIRED = 'NativeIdentityStore.Format.V1'
# The store's whole Format enum, comments aside: three closed versions fixed at construction, each with
# its header ceiling, its reservation version and its slot ceiling.
FORMAT_ENUM = ('enum Format { V1(1, 1, 1), V2(2, 2, 1), V3(2, 2, 2); final int headerCeiling;'
               ' final int reservationVersion; final int slotCeiling;'
               ' Format(int headerCeiling, int reservationVersion, int slotCeiling) {'
               ' this.headerCeiling = headerCeiling; this.reservationVersion = reservationVersion;'
               ' this.slotCeiling = slotCeiling; } }')
# Value, property, settings, reflection and enum selection. This set is refused in every
# production text. The retired lab tool's wider set, with EnumSet, method and variable handles,
# Unsafe, and field and declaring class lookups, is refused in the native sources.
SELECTORS = (r'\bFormat\s*\.\s*valueOf\b', r'\bFormat\s*\.\s*values\s*\(', r'\bEnum\s*\.\s*valueOf\b',
             r'\bFormat\s*\.\s*class\b', r'getEnumConstants')
NATIVE_SELECTORS = SELECTORS + (r'SystemProperties', r'\bSettings\.Global\b', r'java\.lang\.reflect',
                                r'\.forName\(', r'\.getDeclared', r'setAccessible\(', r'\bEnumSet\b',
                                r'\bMethodHandle', r'\bVarHandle', r'\bUnsafe\b', r'\bgetField',
                                r'\bgetDeclaringClass\b', r'\.getMethods?\b', r'\.getConstructors?\b',
                                r'\.newInstance\b')
# A store construction: direct, by simple or qualified name, or a constructor reference.
CONSTRUCTIONS = (java_creation('NativeIdentityStore'), java_constructor_reference('NativeIdentityStore'))
# A Java unicode escape introducer, whatever digits follow: the compiler decodes escapes before
# comments and literals, and reads their digits as Character.digit does, fullwidth ones included. No
# production text carries one, so every backslash followed by u is refused, as is code outside
# printable ASCII.
UNICODE_ESCAPE = r'\\+u+'
# The guard's rules, by the name each violation starts with.
FORMAT_RULES = ('sites', 'format', 'v1', 'v2', 'mention', 'selector', 'enum', 'escape')
HUNK = re.compile(r'@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@')


def patch_sections(text):
    """The added lines of each file section of a unified diff, in order, as (target, text). A
    section starts at its header pair. Hunk counts decide which lines are hunk content, so a
    content line that looks like a header stays in its own section. A malformed hunk refuses."""
    sections, lines, index = [], text.split('\n'), 0
    if lines and lines[-1] == '':
        lines.pop()  # The final newline ends the last line; it starts no empty one.
    while index < len(lines):
        line = lines[index]
        if line.startswith('--- ') and index + 1 < len(lines) and lines[index + 1].startswith('+++ '):
            target = lines[index + 1][4:].split('\t')[0]
            sections.append((target[2:] if target.startswith('b/') else target, []))
            index += 2
            continue
        hunk = HUNK.match(line)
        index += 1
        if hunk is None:
            continue
        if not sections:
            raise ValueError('patch hunk before any file header')
        old, new = (1 if count is None else int(count) for count in hunk.groups())
        added = sections[-1][1]
        while old > 0 or new > 0:
            if index >= len(lines):
                raise ValueError('truncated patch hunk')
            body = lines[index]
            index += 1
            if body.startswith('\\'):
                continue
            if body.startswith('+'):
                added.append(body[1:])
                new -= 1
            elif body.startswith('-'):
                old -= 1
            elif body.startswith(' ') or body == '':
                old -= 1
                new -= 1
            else:
                raise ValueError('malformed patch hunk line')
            if old < 0 or new < 0:
                raise ValueError('patch hunk count mismatch')
    return [(target, '\n'.join(added)) for target, added in sections]


def production_patches(root=ROOT):
    """The production patches under root's patches/, sorted by path: those of the production
    directory and of the AOSP track. Refuses an unknown or malformed entry: anything under
    patches/ but those two directories and the directories of candidate bases recorded in
    upstream/bases, a link, and a directory that holds anything but regular patch, JSON and README
    files. Refuses a missing production directory, and an AOSP track that is missing or does not
    hold the patch its series record names. The record names a patch of the track by its file name,
    so an absolute path or a path into another directory is refused. A candidate's patches are
    never read here."""
    root = Path(root)
    top, production = root / 'patches', (PRODUCTION_PATCHES, AOSP_TRACK)
    if top.is_symlink() or not top.is_dir():
        raise ValueError('patches/ is not a directory')
    names, patches, track = [], [], []
    for directory in sorted(top.iterdir()):
        name = 'patches/' + directory.name
        candidate = CANDIDATE_PATCHES.fullmatch(directory.name)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('unknown entry under patches/, not a directory: ' + name)
        if name not in production and candidate is None:
            raise ValueError('unknown directory under patches/: ' + name)
        if name not in production:
            record = root / 'upstream/bases' / (candidate.group(1) + '.json')
            if record.is_symlink() or not record.is_file():
                raise ValueError('%s names no base recorded in upstream/bases' % name)
        for entry in sorted(directory.iterdir()):
            if (entry.is_symlink() or not entry.is_file()
                    or PATCH_DIRECTORY_FILES.fullmatch(entry.name) is None):
                raise ValueError('malformed patch directory %s: %s' % (name, entry.name))
            if name in production and entry.suffix == '.patch':
                patches.append(entry)
                if name == AOSP_TRACK:
                    track.append(entry.name)
        names.append(name)
    if PRODUCTION_PATCHES not in names:
        raise ValueError('the selected base has no patch directory ' + PRODUCTION_PATCHES)
    if AOSP_TRACK not in names:
        raise ValueError('the AOSP track is missing: ' + AOSP_TRACK)
    if not (root / AOSP_SERIES).is_file():
        raise ValueError('the AOSP track has no series record ' + AOSP_SERIES)
    try:
        named = json.loads((root / AOSP_SERIES).read_text()).get('patch')
    except (ValueError, AttributeError) as error:
        raise ValueError('the AOSP track series is not a JSON record: %s' % error) from error
    if not isinstance(named, str) or named not in track:
        raise ValueError('the AOSP track series names no patch of the track: %r' % (named,))
    return sorted(patches)


def production_texts(root=ROOT):
    """Every production Java text by name: the framework sources, each Java file section of every
    production patch by its added lines, named '<patch>:<file>', and the lab writer fixture. A patch
    is read per file section, never as one merged text. The production patches are the selected
    base's and the AOSP track's; production_patches refuses any other entry under patches/ but a
    candidate base's directory."""
    root = Path(root)
    texts = {path.relative_to(root).as_posix(): path.read_text()
             for path in sorted((root / FRAMEWORK_DIR).glob('*.java'))}
    for patch in production_patches(root):
        name = patch.relative_to(root).as_posix()
        for target, added in patch_sections(patch.read_text()):
            key = '%s:%s' % (name, target)
            if key in texts:
                raise ValueError('patch with two sections for one file: ' + key)
            if target.endswith('.java'):
                texts[key] = added
    texts[WRITER_FIXTURE] = (root / WRITER_FIXTURE).read_text()
    return texts


def native_source(name):
    """Whether a production text is native: a native helper, a section of the native patch, or the
    lab writer route, its fixture and its patch section."""
    return (name in NATIVE_HELPERS or name.startswith(PRODUCTION_NATIVE_PATCH + ':')
            or name == WRITER_FIXTURE or name.startswith(PRODUCTION_WRITER_PATCH + ':'))


def boot_site(text):
    """The offset of the format argument of the one anchored boot construction in a comment free
    Settings section, or None. The method, the construction and the persistence after it each
    occur once, in that order, inside that one method."""
    if text is None:
        return None
    start, site = text.find(METHOD), text.find(CONSTRUCTION)
    end = text.find(BOOT_END, max(start, 0))
    if (text.count(METHOD) != 1 or text.count(CONSTRUCTION) != 1 or text.count(BOOT_END) != 1
            or not 0 <= start < site < end or '\n    }\n' in text[start:end]):
        return None
    return site + len(CONSTRUCTION)


def boot_argument(text, offset):
    """The format argument from offset up to the parenthesis that closes the construction."""
    depth, index = 1, offset
    while depth and index < len(text):
        depth += {'(': 1, ')': -1}.get(text[index], 0)
        index += 1
    return re.sub(r'\s+', ' ', text[offset:index - 1]).strip()


def enum_definition(text):
    """The store's Format enum from its keyword through its closing brace, whitespace collapsed,
    or None when there is not exactly one."""
    found = list(re.finditer(r'\benum\s+Format\s*\{', text))
    if len(found) != 1:
        return None
    depth, index = 0, found[0].end() - 1
    while index < len(text):
        depth += {'{': 1, '}': -1}.get(text[index], 0)
        index += 1
        if depth == 0:
            return ' '.join(text[found[0].start():index].split())
    return None


def format_violations(texts):
    """Every production format violation, as 'rule: detail'.

    sites: exactly one store construction and one Format.V3 in all production texts, both the
    anchored boot construction in readNativeIdentityStoreForBoot of the native patch's Settings
    section. A qualified construction or a constructor reference is a construction too. format:
    that construction passes exactly Format.V3. v1: no production text names Format.V1 or imports
    the enum's constants by wildcard. v2: no production text names Format.V2, the format that the
    images up to B1's passed. mention: only the native helpers and the native patch name
    NativeIdentityStore. selector: no value, property, settings, reflection or enum selection,
    with the wider set in the native sources. enum: the store's Format enum is exactly its three
    closed versions with their header and slot ceilings. escape: no production text carries a Java
    unicode escape, which could hide code from every other rule, or code outside printable ASCII.
    Comments are not code. Constructions are read in the structure view, where literal contents and
    annotations are blank."""
    problems = []
    views = {name: living_views(raw) for name, raw in texts.items()}
    code = {name: kept for name, (kept, _, _) in views.items()}
    structure = {name: shaped for name, (_, _, shaped) in views.items()}
    boot = boot_site(code.get(SETTINGS_SECTION))
    if boot is None:
        problems.append('sites: no anchored boot construction in readNativeIdentityStoreForBoot of '
                        + SETTINGS_SECTION)
        construction = literal = None
    else:
        construction = boot - len(CONSTRUCTION) + CONSTRUCTION.index('new ')
        literal = boot + PRODUCTION.index('Format')
    for name, text in code.items():
        here = name == SETTINGS_SECTION
        for pattern in CONSTRUCTIONS:
            for found in re.finditer(pattern, structure[name]):
                if not (here and found.start() == construction):
                    problems.append('sites: %s constructs a store outside the boot read: %s'
                                    % (name, ' '.join(found.group(0).split())))
        for found in re.finditer(r'\bFormat\s*\.\s*V3\b', text):
            if not (here and found.start() == literal):
                problems.append('sites: %s names Format.V3 outside the boot construction' % name)
        for pattern in (r'\bFormat\s*\.\s*V1\b', r'\bimport\s+static\s+[\w.]*\bFormat\s*\.\s*\*'):
            for found in re.finditer(pattern, text):
                problems.append('v1: %s names the retired format: %s' % (name, found.group(0)))
        for found in re.finditer(r'\bFormat\s*\.\s*V2\b', text):
            problems.append('v2: %s names the previous format: %s' % (name, found.group(0)))
        if (re.search(r'\bNativeIdentityStore\b', text) and name not in NATIVE_HELPERS
                and not name.startswith(PRODUCTION_NATIVE_PATCH + ':')):
            problems.append('mention: %s names NativeIdentityStore outside the native helpers and patch'
                            % name)
        for pattern in NATIVE_SELECTORS if native_source(name) else SELECTORS:
            for found in re.finditer(pattern, text):
                problems.append('selector: %s selects by %s' % (name, found.group(0)))
        # Escapes are refused in the raw text of every production text, comments included, since
        # Java decodes them first.
        for found in re.finditer(UNICODE_ESCAPE, texts[name]):
            problems.append('escape: %s carries the unicode escape %s' % (name, found.group(0)))
        outside = java_code_outside_ascii(views[name][0])
        if outside:
            problems.append('escape: %s carries code outside printable ASCII: %s'
                            % (name, ' '.join('U+%04X' % ord(c) for c in outside)))
    if boot is not None and not code[SETTINGS_SECTION].startswith(PRODUCTION + ');', boot):
        problems.append('format: the boot construction passes %s, not %s'
                        % (boot_argument(code[SETTINGS_SECTION], boot), PRODUCTION))
    store = code.get(STORE)
    definition = None if store is None else enum_definition(store)
    if definition != FORMAT_ENUM:
        problems.append('enum: the store Format enum is not exactly V1(1, 1, 1), V2(2, 2, 1) and V3(2, 2, 2): %s'
                        % definition)
    return problems


def format_rules(texts):
    """The guard rules these production texts trip."""
    return {problem.split(':', 1)[0] for problem in format_violations(texts)}


def boot_literal(texts=None):
    """The format argument of the anchored boot construction in the native patch, or None."""
    texts = production_texts() if texts is None else texts
    code = living_code(texts.get(SETTINGS_SECTION, ''))
    boot = boot_site(code)
    return None if boot is None else boot_argument(code, boot)


def facade_default(text=None):
    """The format the host Settings facade constructs when a test passes none, or None. Both
    constructors without a format must reach the one default."""
    text = (ROOT / FACADE).read_text() if text is None else text
    found = re.findall(r'^    Settings\(Path existing, boolean initialize\) '
                       r'\{ this\(existing, initialize, ([A-Za-z0-9_.]+)\); \}$', text, re.M)
    if len(found) != 1 or text.count('\n    Settings() { this(null, true); }\n') != 1:
        return None
    return found[0]


def b2_forward(text):
    """The text with the floor's boot literal Format.V2 replaced by Format.V3: the whole B2 change
    of the native patch and of the adapted Settings, and the code change of the host facade's
    default. None unless exactly one previous literal and no production literal occur. Comparisons
    with B1's floor use it to allow exactly that change and nothing else."""
    old, new = PREVIOUS + ');', PRODUCTION + ');'
    if text.count(old) != 1 or text.count(new):
        return None
    return text.replace(old, new, 1)


# B1's image, the rollback floor, whose boot read constructs Format.V2. Every input that a run over
# the floor reads is its Git object at the floor revision, never the working tree, pinned here by
# repository path with the SHA-256 of that object. This is the floor's own manifest: the 24bfb6a
# archive's manifest supplies none of it, and its fixtures, stubs, fragments, supports and harness
# template are not the floor's. The forward rule gives the current patch from the floor's byte for
# byte, and the current adapted Settings from the floor's, rebuilt from the pinned canonical
# copies. The lifecycle runner's floor model compiles B1's own reader check with B1's product, host
# facade and stubs, its harness cut from B1's candidate Settings by B1's fragments, and its test
# supports, all from these pins.
FLOOR = 'da790b1748b14cfa7cec1db4ee44b20f608bdf5a'
# The native patch and its profile at their paths in the trees of B1's image, the floor, and of
# B2's, both built on 2026081300. They stay when the selected base, and with it the production
# patch directory, moves.
NATIVE_PATCH = 'patches/grapheneos-2026081300/native-principal-pins.patch'
NATIVE_PROFILE = 'patches/grapheneos-2026081300/native-principal-pins.json'
# The floor's directories, frozen with it, and its stub directories, whose floor trees are pinned
# whole but for the unused XML stub.
FLOOR_PLATFORM = 'owner/tests/platform/'
FLOOR_FRAMEWORK_DIR = 'owner/platform/framework/'
FLOOR_STUB_DIRECTORIES = ('native_principal_stubs', 'native_principal_xml_stubs')
FLOOR_PIN_GROUPS = (
    # The native patch and its profile, which the candidate rebuild reads.
    ('patches/grapheneos-2026081300/', {
        'native-principal-pins.patch': '59300e3d12a59dcb33acadc104894fd4b015e9fcc14bf456a09a07aee015a04e',
        'native-principal-pins.json': '37e180b0b4bf7576aee23be6d7298c4c1af9e1037688523be56c20d59547d8f2'}),
    # The six native helpers.
    (FLOOR_FRAMEWORK_DIR, {
        'NativePrincipalPins.java': 'c8b58f864fedb0fc522bdb622b9dee150a3407d967b2f703011fcb1b2de4401b',
        'NativePrincipalManager.java': '7c76194cc441507f2ffe8224f6e9e4d013b6fabadde56723430fd18d17f6fcee',
        'NativeIdentityRecords.java': '4be9c8a0135d3793bb4153e9dc794c2afbf6e4bdbc3466d447b883fe30e0b032',
        'NativeIdentityStore.java': 'e4cd321662733cc781566689e9c0436d7865010ce446548e5fea9ffbd7b85c57',
        'NativeIdentityPersistence.java': 'a3d6d23e3378611f6d82df07a4ede7ba7949f1f69cc24873a788a64d24e1604b',
        'NativePrincipalRecovery.java': 'e6370a2bc822c78602c97b3a04803916184095a6dc796d1360a48b47791fbda8'}),
    # The guarded fixtures: the app ID map and the strict writer.
    (FLOOR_PLATFORM, {
        'AppIdSettingMap.java.inc': 'ac0721c8c98e1efbe17b64358f29a30ae514ceddff51f48959bd6249b256e9f7',
        'ResilientAtomicFile.java.inc': 'b9b0a369d3519713d16de6bf7ec574bcad5ae6c8d3132121a6124b8b2f4d1130'}),
    # The host facade and stubs.
    (FLOOR_PLATFORM + 'native_principal_stubs/', {
        'android/content/pm/Signature.java': '194cccdf1a00bb85a3189525ba7a43f88f30e3361660e590e0908321b3b8d644',
        'android/content/pm/SigningDetails.java': '05e0e97105a55f69bde585f576cb04a59960ff999be3dd8a9fbaecfa02dedac2',
        'android/content/pm/UserInfo.java': 'ff81825584932dcb182fcb44d12b1f27f8d71f6e78baf4a14d2ad641956a64fe',
        'android/os/Process.java': 'ffe360d2de8e077132bb80a71d05695472221a5c794410b0bc2fe2f69ce0e2d1',
        'android/os/UserHandle.java': '2dfd22758b83fc63f8419c5de8813346ba744ca0daddf266ab9fd7cb21b47ec5',
        'android/util/Base64.java': '4316c03a833ecafde0b01b5dd66925f6d8d1d8c0cdf82e89dee80f3ffe927f1a',
        'android/util/Log.java': '45dfc0e11053b0273901815c020112d8bd2e15a33bac059ba1a3f98cf2d5b056',
        'com/android/server/LocalServices.java': 'c0adc1f494840fcb58d1acb6ac1943e56d63147667d2a13647913939ccc82c10',
        'com/android/server/pm/PackageManagerService.java':
            'd3cc9ab333fbfbc5f291ae3606e1daca5f0eaa5a7b0630f6858042559e71a1c7',
        'com/android/server/pm/PackageManagerTracedLock.java':
            'd4f07b6fe6761da9228129c7c25d4002f543f99f92ca2047720441ff3c624d3c',
        'com/android/server/pm/PackageSetting.java': '9c1da430837ff410b9fededd51f4079521257221060ef5ab13c73cf0934c77e4',
        'com/android/server/pm/SettingBase.java': 'c2389dc480ad1e713f5f3c15037c7b7388569c237a7ecda586e4bae29fc52232',
        'com/android/server/pm/Settings.java': 'a314430a8f0970cfae1cf8df3e5f1532da7b5eb91e3a206b642c20bc332b5dd1',
        'com/android/server/pm/SharedUserSetting.java':
            '84e80c3dbdbadb4cf2e77801b7344eaebf6ddb75b68353ee9c2021edb3ea8929',
        'com/android/server/pm/UserManagerInternal.java':
            'e0a8b11a125c2684fdd7231fcf434ad88a73631abf03e982d833519fd93e2842',
        'com/android/server/pm/pkg/PackageStateInternal.java':
            '8810412ebb8dd0bdc504ab6aa4e64487f754a71f8415a382d82f900c8168a6e1',
        'com/android/server/pm/pkg/PackageUserStateInternal.java':
            'bd82da9aeffde182bce106847cfeeebcc02cbfb1de94474eb27e35f963fe0fc6',
        'com/android/server/utils/SnapshotCache.java':
            'b9775ad4dc2c3b9d9affe27be93cf2a097437307a077fa5b7fe10106d43e334c',
        'com/android/server/utils/WatchedArrayList.java':
            'b1a32b1ac8a4bffab749749be8800f030dde82c2ace07e53b5aa41a11e4523ec',
        'com/android/server/utils/WatchedSparseArray.java':
            '689d2bd1d6bd6fe112b5d0a9ebb75dd8573731441770e866ac1f0d516c3a172c',
        'com/android/server/utils/Watcher.java': '8fe7fe546e40f3d6561af8b897e02e20dc5a03548172d7dbefde6436db172912'}),
    # The file and XML stubs, the unused XML stub aside.
    (FLOOR_PLATFORM + 'native_principal_xml_stubs/', {
        'android/annotation/NonNull.java': '6ddc0b4d052155af25bb53e667a9af619e37627895d7f3931df37ce03ce2b40d',
        'android/annotation/Nullable.java': '240f7f85d753d961120cdab80dfc49d1af63a1dc11db0e68d5532c8407689822',
        'android/os/FileUtils.java': '9852208a316783e5a76141551181bd6ec1c6f41275e67f0c334ec7d6a39f5db2',
        'android/os/ParcelFileDescriptor.java': '2ca584995f00f3608884c7850db8bc0592fc66ffad9180fbb520ac9dc0bdfbce',
        'android/system/ErrnoException.java': '80e2fd2821ed73ad4c5239d174d55735f86e850195bed37be90aac12acfb7324',
        'android/system/Os.java': '6cb0f0e9bc7af27a872e1dc9d3076f4cba7100c3ed6d2a973de7508a6d673d24',
        'android/system/OsConstants.java': 'a8a42f40daafd3f3d3115c09ccdf4aaaad4c2d3c76d6093a19140b18cfe8d15d',
        'android/system/StructStat.java': '9c79371a592cdf8e19f4b76e4229445725430ad390e4ffca95bfd5845de2890c',
        'android/util/Log.java': '1179e9289ee751a66dfa1fc3167ccae3eb09d1bdffe0198150f2b91cd5ed6326',
        'android/util/Slog.java': 'd05edc6412193d1027a8051abbf5dc9df082bf8e04173c09e01de84584249754',
        'com/android/internal/annotations/VisibleForTesting.java':
            '5f0d808d0ce0185826a8a145fd2ec7735ae185ade8ac3298af2cb5c24550371b',
        'com/android/internal/util/XmlUtils.java': 'd02b0c70ede9298e475a8975c268622a7b48aefc504f3c1c64559b10ef3118e8',
        'com/android/modules/utils/TypedXmlPullParser.java':
            '74bb7ccb4e8ffbbc19f635ab9a6c3224ab1be238f812389a93cc1bf9e4940b7f',
        'com/android/modules/utils/TypedXmlSerializer.java':
            '67cc6ce0438d60ad059b20d7d62be32b17950d4ff495bf5d9640f7170ee8ca17',
        'com/android/server/security/FileIntegrity.java':
            '34850de514202aa02bbf8f3ccfd0e3e2c016f37d5c66a3703de65bc56c8a4a78',
        'libcore/io/IoUtils.java': 'd5c7d4e663fde5f3e0d5a1d666055af45b9d0e87183b9309a8a173c108be640b',
        'org/xmlpull/v1/XmlPullParser.java': 'ed18ef0bf4db43202e7720502738031223361592aca7bbb99e26fdb909fd6248',
        'org/xmlpull/v1/XmlPullParserException.java':
            'a89e65c01d99a7ae49f44532d717c746623c76705aff0ddd9a9177b5e0009068'}),
    # The recovery fragments, by which the floor harness is cut and checked.
    (FLOOR_PLATFORM + 'native_recovery_fragments/', {
        'identity.java.inc': '04a06cad1791ba2b3a22b24152469f5b32da2404e91a863961569238e42ff7ce',
        'system-cleanup.java.inc': 'a3fe313963a15e2cd8b7f9d5707ae89f53f470525343ff446e3904e06e72207c',
        'parse-failure.java.inc': 'f769bea3670ac3611d112b1b771b9d26abbb0ba5508a549dd746040e106214e6',
        'install-markers.java.inc': 'b0c2f79d9e02f99866ed50e832abb83913c90bab7ed7a13ace4aee1d5b279332',
        'system-delete.java.inc': '22f757c8cd48513a9003093561872b02d686f251e01ab2a08a97d8b3f2aa63c3',
        'path-safety.java.inc': 'c1db3fe3be384b360761c7953ffb12457fd8b10ecc16cdec6fcf73a99732bb6a',
        'restore-capacity.java.inc': '94f73c5bc31d28d85f51c678b60daa7eeaae3482e15840210895cb62f58ecdef',
        'admission.java.inc': 'f6fb1d4f8dd53dbb712f35f8832e51735657a4e5c1be948512c6d9f9b33fc8eb',
        'restore-history.java.inc': 'fabd0161b440933cd61d2234667bdeb72a5119a0b3c00eb0c9e61b30d316b444',
        'stored-history.java.inc': '08afa193e032e5eb3717a19584b90acaf81b1bb4541bd08cca298cc85dcf1b9a',
        'scan.java.inc': '369d036a9931ec07f0689f55717e7945d59d2da9a449360163d16df0591f719a',
        'recovery-seeding.java.inc': '604059a49fa26c8947803f40dd1f1c032b24d5875c7b84f299e79149c0a41727',
        'boot-facts.java.inc': 'feef1495ce2b94302a140fc6df252a6d7f1fbb910bc8452cbbf67778c4ade6c7',
        'retired-boot.java.inc': '02a35b1005f071c15a78e1f16e00f16958ed9922bd1f3d8c900a145893d10178',
        'deferral.java.inc': 'ac1e3b8e4ef98fb593224673824d0942f7bb38d3b9986f0cb7d59eef0909a8dd',
        'observation.java.inc': '3ec3bda6a37eec0752ecdd2363a61df6c9eebd38966fc0eaa0f16eaa28f0d709',
        'release-finish.java.inc': 'bd8d21c0189304e5cb31d086ef7881cb46f3e5293079d242366dd03584e29eec',
        'diagnostic-dump.java.inc': '17a8d470177321e79918c057a96fe6084cc9041ad124db334abda1417bd50f03'}),
    # The history harness template, its body inputs, the test supports and the reader check.
    (FLOOR_PLATFORM, {
        'NativeHistoryHarness.java.in': '4671b3855f935cf7b270901a3910283a0c833d8b0a1e2c51c0046c7ed8c0b370',
        'native_history_api/b2/body-inputs.java.inc':
            '59f847a99f67c56d1803d561e9c29914cbe02f28e876a0e1731d943fcb493f84',
        'NativeHeaderTestSupport.java': 'bc22ff336e19f201d04ec72865ba885caca0693e3d6385d06c4542f64abf2d9e',
        'NativeBindingTestSupport.java': '2426ad2e672f28b762444727c9c34b9987fe5db4d7a1927a6c1d74b7ba8c199d',
        'NativeHistoryTestSupport.java': '60a69f504b04af32e5f7176c8ae9e5f751722a83942cf008942c11f013f31ff1',
        'NativeLifecycleReaderCheck.java': 'cac8a37b8e55badea71cfea8a20122eb8d451afbda7b34b8e5366c6aa88a7584'}),
)
FLOOR_SHA256 = {directory + relative: digest for directory, group in FLOOR_PIN_GROUPS
                for relative, digest in group.items()}
# The floor's adapted Settings, as its pinned profile states it.
FLOOR_SETTINGS_SHA256 = '4d851032afedd43ddadacdbc026ac62e0ea22c218a8fb0c8f59a70d67a452eeb'


def floor_bytes(path):
    """One input of B1's floor: its Git object at the floor revision, refused unless the floor
    manifest pins it with that SHA-256. The working tree is never read. The floor's one loader."""
    digest = FLOOR_SHA256.get(path)
    if digest is None:
        raise ValueError('unpinned floor input: ' + path)
    data = git_bytes(FLOOR, path)
    if sha(data) != digest:
        raise ValueError('floor input drift: ' + path)
    return data


def floor_paths(directory):
    """The pinned floor inputs below one directory, refused unless they are exactly the floor's Git
    tree there, the unused XML stub aside, so no file of that tree goes unpinned or unread."""
    pinned = sorted(path for path in FLOOR_SHA256 if path.startswith(directory))
    tree = [path for path in git_paths(FLOOR, directory) if not path.endswith('/Xml.java')]
    if pinned != tree:
        raise ValueError('floor tree drift: %s unpinned %s, absent %s' % (
            directory, sorted(set(tree) - set(pinned))[:3], sorted(set(pinned) - set(tree))[:3]))
    return pinned


def floor_problems():
    """The floor manifest's own consistency: every pin is its Git object at the floor revision, each
    pinned stub tree is exactly the floor's tree there, and the boot read of the floor's patch
    constructs the previous format, Format.V2, as B1's image does."""
    problems = []
    try:
        for directory in FLOOR_STUB_DIRECTORIES:
            floor_paths(FLOOR_PLATFORM + directory + '/')
        for path in sorted(FLOOR_SHA256):
            floor_bytes(path)
        sections = dict(patch_sections(floor_bytes(NATIVE_PATCH).decode()))
        if boot_literal({SETTINGS_SECTION: sections.get(integration.SETTINGS, '')}) != PREVIOUS:
            problems.append('the floor patch does not construct %s at its boot read' % PREVIOUS)
    except ValueError as error:
        problems.append('floor pins: %s' % error)
    return problems


def floor_outputs(pinned, scratch=None):
    """The floor's ten framework outputs: its patch, read from its Git object, applied to the pinned
    canonical copies as the profile tool applies the current patch, each output checked against the
    candidate of the floor's pinned profile. The patch applies in a temporary directory, or in
    scratch, a fresh directory outside the repository that is left to the caller, so a caller can
    rebuild the floor with the working tree closed. Pure patch reproduction; no compiler."""
    value = json.loads(floor_bytes(NATIVE_PROFILE))
    if ([row['path'] for row in value['files']] != list(integration.FILES)
            or [row['candidate_sha256'] for row in value['files'] if row['path'] == integration.SETTINGS]
            != [FLOOR_SETTINGS_SHA256]):
        raise ValueError('floor profile drift')
    if scratch is None:
        with tempfile.TemporaryDirectory(prefix='andrix-b2-floor-') as directory:
            output = floor_patch_outputs(pinned, value, Path(directory))
    else:
        if Path(scratch).exists() or not outside_repository(scratch):
            raise ValueError('floor scratch is not fresh and outside the repository: %s' % scratch)
        Path(scratch).mkdir(parents=True)
        output = floor_patch_outputs(pinned, value, Path(scratch).resolve())
    for row in value['files']:
        if sha(output[row['path']]) != row['candidate_sha256']:
            raise ValueError('floor candidate drift: ' + row['path'])
    return output


def floor_patch_outputs(pinned, value, directory):
    """The floor patch applied in directory to the pinned canonical copies that the floor profile
    value names, each refused unless it has the profile's upstream bytes: the ten outputs."""
    tree, patch = directory / 'tree', directory / 'floor.patch'
    patch.write_bytes(floor_bytes(NATIVE_PATCH))
    for row in value['files']:
        source = pinned / row['path']
        if source.is_symlink() or not source.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        data = source.read_bytes()
        if sha(data) != row['upstream_sha256']:
            raise ValueError('wrong pinned input: ' + row['path'])
        (tree / row['path']).parent.mkdir(parents=True, exist_ok=True)
        (tree / row['path']).write_bytes(data)
    result = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                             '-p1', '-i', str(patch)], cwd=tree, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('floor patch failed: ' + result.stderr.decode(errors='replace'))
    if ({path.relative_to(tree).as_posix() for path in tree.rglob('*') if path.is_file()} != set(integration.FILES)
            or any(path.is_symlink() for path in tree.rglob('*'))):
        raise ValueError('unexpected floor patch output')
    return {row['path']: (tree / row['path']).read_bytes() for row in value['files']}


def floor_forward(pinned):
    """B2 against B1's floor over the pinned canonical copies: the current ten outputs, each the
    current profile's candidate, beside the floor's. The forward rule gives the current adapted
    Settings from the floor's, and every other output is equal. Returns the record and its
    problems."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    current, floor = integration.targets(original, value), floor_outputs(pinned)
    old, new = floor[integration.SETTINGS], current[integration.SETTINGS]
    forwarded = b2_forward(old.decode())
    record = {'revision': FLOOR, 'outputs': {name: sha(floor[name]) for name in integration.FILES},
              'differing': sorted(name for name in integration.FILES if floor[name] != current[name]),
              'settings_byte_differences': sum(a != b for a, b in zip(old, new)) if len(old) == len(new) else None,
              'settings_forward': forwarded is not None and forwarded.encode() == new}
    problems = []
    if record['differing'] != [integration.SETTINGS]:
        problems.append('floor outputs other than the adapted Settings differ: %s' % record['differing'])
    if not record['settings_forward']:
        problems.append('the adapted Settings is not the floor one with its boot literal moved forward')
    return record, problems


def facade_violations(texts=None, facade=None):
    """The host facade's default format is the literal of the patch's boot construction."""
    literal, default = boot_literal(texts), facade_default(facade)
    if literal is None or default != literal:
        return ['host Settings facade default %s differs from the boot construction literal %s'
                % (default, literal)]
    return []


def surface_violations():
    """The B1 production surface: no Snapshot overload beside plans, one fixed format, and the
    encoder's own byte measure. The format guard pins the Format enum itself."""
    problems = []
    store = living_code((ROOT / STORE).read_text())
    persistence = living_code((ROOT / PERSISTENCE).read_text())
    records = living_code((ROOT / FRAMEWORK_DIR / 'NativeIdentityRecords.java').read_text())
    manager = living_code((ROOT / MANAGER).read_text())
    if re.search(r'reservePending\s*\(\s*NativePrincipalPins\s*\.\s*Snapshot', persistence):
        problems.append('reservePending keeps a Snapshot overload')
    if re.search(r'projectReservation\s*\([^)]*Snapshot', persistence):
        problems.append('projectReservation keeps a Snapshot overload')
    if len(re.findall(r'\bboolean\s+reservePending\s*\(', persistence)) != 1:
        problems.append('reservePending is not one plan method')
    if len(re.findall(r'\bHeader\s+projectReservation\s*\(', persistence)) != 1:
        problems.append('projectReservation is not one method')
    if len(re.findall(r'NativeIdentityStore\s*\(\s*File\s+root\s*,\s*Format\s+format\s*\)', store)) != 1 \
            or re.search(r'NativeIdentityStore\s*\(\s*File\s+root\s*\)', store):
        problems.append('store is not constructed only with an explicit format')
    if len(re.findall(r'private final Format format;', store)) != 1 \
            or len(re.findall(r'\bformat\s*=\s*Objects\.requireNonNull\(format', store)) != 1:
        problems.append('store format is not one final field assigned at construction')
    if 'headerBody(version, lineage, lastId, copy).length()' not in records:
        problems.append('encodedHeaderLength is not the encoder measure')
    if persistence.count('NativeIdentityRecords.encodedHeaderLength(') != 1:
        problems.append('projection does not measure exactly once')
    if 'currentSignerSha256' not in manager or 'ownedPlan(' not in manager:
        problems.append('manager plan provenance missing')
    return problems


def mutant_sources():
    """Each B1 mutant applied to the current source text, anchored exactly once."""
    result = {}
    for name, (path, replacements, suites) in MUTANTS.items():
        text = (ROOT / path).read_text()
        for old, new in replacements:
            text = replace_once(text, old, new)
        result[name] = (path, text, suites)
    return result


def one_token_patch(old, new):
    """A one token Settings patch, as the retired lab format was, from one boot format literal to
    another."""
    first, second, indent = CONSTRUCTION.split('\n')
    return ('--- a/%s\n+++ b/%s\n@@ -611,7 +611,7 @@\n' % (integration.SETTINGS, integration.SETTINGS)
            + '         if (mNativeIdentityPersistence != null) throw new IllegalStateException('
              '"Native store loaded twice");\n'
            + ' %s\n %s\n-%s%s);\n+%s%s);\n %s' % (first, second, indent, old, indent, new, BOOT_END)
            + '         NativeIdentityStore.Loaded loaded = mNativeIdentityPersistence.load();\n'
            + '         // This is negative preservation evidence, never signer/owner identity.\n')


# Where each guard mutant's one token version 1 patch lands under patches/: beside the production
# native patch, and in another directory. The layout refuses that directory before any rule reads
# it; the mutant keeps the rules' own reading of it.
ONE_TOKEN_PATHS = {
    'one-token-v1-patch-beside-native': PRODUCTION_PATCHES + '/native-store-format-v1.patch',
    'one-token-v1-patch-other-directory': 'patches/lab/any-name.patch'}
# Code the guard mutants insert before the persistence constructor, or pass at the boot site.
HOST_CONSTRUCTION = ('    static NativeIdentityPersistence host(java.io.File root) {\n'
                     '        return new NativeIdentityPersistence(new NativeIdentityStore(root,\n'
                     '                NativeIdentityStore.Format.V3));\n    }\n\n')
REFLECTIVE_WRITE = ('    static void copyFormat(NativeIdentityStore store, NativeIdentityStore from)\n'
                    '            throws ReflectiveOperationException {\n'
                    '        java.lang.reflect.Field field = NativeIdentityStore.class.getDeclaredField("format");\n'
                    '        field.setAccessible(true);\n'
                    '        field.set(store, field.get(from));\n    }\n\n')
COMPLEMENT = ('    static NativeIdentityStore.Format otherFormat(NativeIdentityStore store) {\n'
              '        return java.util.EnumSet.complementOf(java.util.EnumSet.of(store.format()))\n'
              '                .iterator().next();\n    }\n\n')
SELECTED = ('NativeIdentityStore.Format.valueOf(android.os.SystemProperties.get('
            '"persist.andrix.native_format", "V3")));\n')
QUALIFIED = ('    static NativeIdentityStore qualified(java.io.File root, NativeIdentityStore.Format format) {\n'
             '        return new com.android.server.pm.NativeIdentityStore(root, format);\n    }\n\n')
REFERENCE = ('    static final java.util.function.BiFunction<java.io.File, NativeIdentityStore.Format,\n'
             '            NativeIdentityStore> STORES = %sNativeIdentityStore::new;\n\n')
DECLARING_FIELD = ('    static Object retired(NativeIdentityStore store) throws ReflectiveOperationException {\n'
                   '        return store.format().getDeclaringClass().getField("V1").get(null);\n    }\n\n')
# Java ends this comment at the escaped line break and compiles the rest of the line as code.
HIDDEN = ('    // \\u000a static final NativeIdentityStore HIDDEN = new NativeIdentityStore('
          'new java.io.File("/"), NativeIdentityStore.Format.V1);\n')
RETIRED_NAME = ('    static NativeIdentityStore.Format earlierFormat() {\n'
                '        return NativeIdentityStore.Format.V1;\n    }\n\n')
PREVIOUS_NAME = ('    static NativeIdentityStore.Format floorFormat() {\n'
                 '        return NativeIdentityStore.Format.V2;\n    }\n\n')
# A non native framework source that names the store, and the non native class it goes in.
MENTION = '    private static final String STORE = "NativeIdentityStore";\n'
NON_NATIVE = FRAMEWORK_DIR + 'CeStorageAccessTracker.java'


def guard_mutants():
    """Production format defects, each with the exact set of guard rules it must trip."""
    texts = production_texts()
    settings, persistence = SETTINGS_SECTION, FRAMEWORK_DIR + 'NativeIdentityPersistence.java'
    manager = PRODUCTION_NATIVE_PATCH + ':' + integration.PREFIX + 'PackageManagerService.java'
    boot = CONSTRUCTION + PRODUCTION + ');\n'
    anchor = '    NativeIdentityPersistence(NativeIdentityStore store) {\n'

    def changed(*edits):
        result = dict(texts)
        for name, old, new in edits:
            result[name] = replace_once(result[name], old, new)
        return result

    # The boot method's head, construction and persistence move to the start of the next file's
    # section. Read as one merged text, that anchored construction would still be found.
    head = texts[settings][texts[settings].index(METHOD):texts[settings].index(BOOT_END) + len(BOOT_END)]
    other_section = changed((settings, head, ''))
    other_section[manager] = head + texts[manager]
    outside = changed((settings, boot, ''))
    outside[settings] = replace_once(outside[settings], METHOD,
                                     '    void openNativeIdentityStoreLPw() {\n' + boot + '    }\n\n' + METHOD)
    second = boot.replace('mNativeIdentityStore =', 'NativeIdentityStore second =', 1)
    result = {
        'regression-to-v1': (changed((settings, boot, CONSTRUCTION + RETIRED + ');\n')), {'format', 'v1'}),
        'second-construction': (changed((settings, BOOT_END, BOOT_END + second)), {'sites'}),
        'framework-construction': (changed((persistence, anchor, HOST_CONSTRUCTION + anchor)), {'sites'}),
        'other-file-section': (other_section, {'sites'}),
        'value-and-property-selection': (changed((settings, boot, CONSTRUCTION + SELECTED)), {'format', 'selector'}),
        'reflective-field-write': (changed((persistence, anchor, REFLECTIVE_WRITE + anchor)), {'selector'}),
        'enumset-complement': (changed((persistence, anchor, COMPLEMENT + anchor)), {'selector'}),
        'enum-version-swap': (changed((STORE, 'V1(1, 1, 1),', 'V1(2, 2, 1),'), (STORE, 'V2(2, 2, 1),', 'V2(1, 1, 1),')),
                              {'enum'}),
        # The production format no longer reading version 2 slots as supported state: its slot
        # ceiling lowered to the floor's.
        'slot-ceiling-regression': (changed((STORE, 'V3(2, 2, 2);', 'V3(2, 2, 1);')), {'enum'}),
        # The boot read constructs the floor's format again, which reads version 2 slots only as
        # evidence.
        'regression-to-v2': (changed((settings, boot, CONSTRUCTION + PREVIOUS + ');\n')), {'format', 'v2'}),
        'v2-alone': (changed((persistence, anchor, PREVIOUS_NAME + anchor)), {'v2'}),
        'construction-outside-boot': (outside, {'sites'}),
        'qualified-construction': (changed((persistence, anchor, QUALIFIED + anchor)), {'sites'}),
        'constructor-reference': (changed((persistence, anchor, REFERENCE % '' + anchor)), {'sites'}),
        'qualified-constructor-reference': (
            changed((persistence, anchor, REFERENCE % 'com.android.server.pm.' + anchor)), {'sites'}),
        'declaring-class-field': (changed((persistence, anchor, DECLARING_FIELD + anchor)), {'selector'}),
        # Every rule reads the compiler's translation, so the construction the escape hides trips the
        # site and format rules beside the escape rule.
        'unicode-escape': (changed((persistence, anchor, HIDDEN + anchor)), {'escape', 'sites', 'v1'}),
        'format-alone': (changed((settings, boot, CONSTRUCTION + 'productionFormat());\n')), {'format'}),
        'v1-alone': (changed((persistence, anchor, RETIRED_NAME + anchor)), {'v1'}),
        'mention-alone': (changed((NON_NATIVE, 'public final class CeStorageAccessTracker {\n',
                                   'public final class CeStorageAccessTracker {\n' + MENTION)), {'mention'}),
        'harmless-unicode-escape': (changed((persistence, anchor, '    // caf\\u00e9\n' + anchor)), {'escape'}),
        'unicode-carriage-return-escape': (changed((persistence, anchor, HIDDEN.replace('\\u000a', '\\u000d')
                                                    + anchor)), {'escape', 'sites', 'v1'}),
        'creation-with-type-arguments': (changed((persistence, anchor, QUALIFIED.replace(
            'new com.android.server.pm.NativeIdentityStore(', 'new <String> NativeIdentityStore(') + anchor)), {'sites'}),
        'annotated-qualified-creation': (changed((persistence, anchor, QUALIFIED.replace(
            'new com.android.server.pm.NativeIdentityStore(', 'new @A com.android.server.pm.@B(x = {1}) NativeIdentityStore(')
            + anchor)), {'sites'}),
        'annotated-creation-holding-a-parenthesis': (changed((persistence, anchor, QUALIFIED.replace(
            'new com.android.server.pm.NativeIdentityStore(', 'new @P7Mark("(") NativeIdentityStore(') + anchor)), {'sites'}),
        'nested-annotation-creation': (changed((persistence, anchor, QUALIFIED.replace(
            'new com.android.server.pm.NativeIdentityStore(', 'new @P7Outer(@P7Middle(@P7Inner(1))) NativeIdentityStore(')
            + anchor)), {'sites'}),
        'code-outside-ascii': (changed((persistence, anchor, '    private static final int MARK\u200c = 0;\n\n' + anchor)),
                               {'escape'}),
        'computed-method-lookup': (changed((persistence, anchor,
            '    static Object lookup() throws ReflectiveOperationException {\n'
            '        return NativePrincipalPins.class.getMethod("finish" + "Release", NativePrincipalPins.Pin.class);\n'
            '    }\n\n' + anchor)), {'selector'}),
        'constructor-reference-with-type-arguments': (
            changed((persistence, anchor, (REFERENCE % '').replace('::new', ':: <String> new') + anchor)), {'sites'}),
        'fullwidth-unicode-escape': (changed((persistence, anchor, HIDDEN.replace('\\u000a', '\\u\uff10\uff10\uff10\uff41')
                                              + anchor)), {'escape', 'sites', 'v1'}),
        'non-native-unicode-escape': (changed((NON_NATIVE, 'public final class CeStorageAccessTracker {\n',
                                               'public final class CeStorageAccessTracker {\n' + HIDDEN)),
                                      {'escape', 'mention', 'sites', 'v1'}),
    }
    for name, path in ONE_TOKEN_PATHS.items():
        patched = dict(texts)
        for target, added in patch_sections(one_token_patch(PRODUCTION, RETIRED)):
            patched['%s:%s' % (path, target)] = added
        result[name] = (patched, {'v1', 'mention'})
    return result


def verify_candidate(pinned):
    """Rebuild the ten framework outputs from pinned canonical copies with the current patch.
    Returns each output's hash and whether it matches the profile candidate. Pure Python and
    /usr/bin/patch; no compiler."""
    value = integration.profile()
    original = {}
    for row in value['files']:
        path = pinned / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('pinned framework copy missing: ' + row['path'])
        original[row['path']] = path.read_bytes()
    output = integration.targets(original, value)
    return {name: {'sha256': sha(output[name]), 'candidate': sha(output[name]) == row['candidate_sha256']}
            for row in value['files'] for name in [row['path']]}


def twin_problems(predictions):
    """The production twins are exactly the cases outside NO_TWIN, each a V3 run printed right after
    its case; the production mutants change only the production format's enum line and are predicted
    to fail production twins alone; the default check's controls name known stores. Pure."""
    problems = []
    if not set(NO_TWIN) | set(TWIN_NAMES) <= set(FOCUSED_NAMES) or not all(NO_TWIN.values()):
        problems.append('a case without a twin is no focused case, or has no reason')
    if (len(PRODUCTION_TWINS) + len(NO_TWIN) != len(FOCUSED_NAMES) or len(FOCUSED_RUNS) != len(FOCUSED_NAMES)
            + len(PRODUCTION_TWINS) or set(FOCUSED_RUNS) != set(FOCUSED_NAMES) | set(PRODUCTION_TWINS)
            or set(FOCUSED_NAMES) & set(PRODUCTION_TWINS)
            or not all(twin.startswith(('V3 / ', 'V3 gate / ')) for twin in PRODUCTION_TWINS)):
        problems.append('the production twins of b1 focused differ from its cases')
    if (ROOT / STORE).read_text().count(PRODUCTION_ENUM) != 1:
        problems.append('the production format enum line is not found once')
    for name in PRODUCTION_MUTANTS:
        expected = predictions['b1_mutants_caught_at_least'].get(name, ())
        if MUTANTS.get(name, (None,))[0] != STORE or not expected or not set(expected) <= set(PRODUCTION_TWINS):
            problems.append('production mutant %s is not predicted against production twins alone' % name)
    if (set(DEFAULT_DIFFERS) != {'V1', 'V2'} or not set(DEFAULT_DIFFERS['V2']) <= set(DEFAULT_DIFFERS['V1'])
            or not set(DEFAULT_DIFFERS['V1']) < set(DEFAULT_CASES)):
        problems.append('the default controls name stores the check does not hold')
    # The check's Java holds the same stores, in order, and the same control sets.
    code = strip_java_comments((ROOT / PLATFORM / (DEFAULT_TEST + '.java')).read_text())
    if tuple(re.findall(r'\ball\.put\("([^"]+)"', code)) != DEFAULT_CASES:
        problems.append('the default check holds other stores than DEFAULT_CASES')
    for format_name, wanted in sorted(DEFAULT_DIFFERS.items()):
        found = re.findall(r'\b%s_DIFFERS = Set\.of\(([^;]*)\);' % format_name, code)
        if len(found) != 1 or sorted(re.findall(r'"([^"]+)"', found[0])) != sorted(wanted):
            problems.append('the default check\'s %s control differs from DEFAULT_DIFFERS' % format_name)
    if (ROOT / FACADE).read_text().count(DEFAULT_ROUTE % PRODUCTION) != 1:
        problems.append('the facade default route is not found once')
    return problems


def guard_mutant_problems():
    """Each guard mutant that trips other rules than its own."""
    problems = []
    for name, (mutated, rules) in guard_mutants().items():
        tripped = format_rules(mutated)
        if tripped != rules:
            problems.append('guard mutant %s tripped %s, not %s' % (name, sorted(tripped), sorted(rules)))
    return problems


def format_guard():
    """The production format guard alone: the layout of patches/, the violations of the production
    texts, and each guard mutant over them. Pure and read only, and it needs no Git history, so a
    scratch checkout that selects a candidate base runs it on the candidate's patches."""
    try:
        problems = format_violations(production_texts())
    except (OSError, ValueError) as error:
        return ['production texts: %s' % error]
    try:
        problems += guard_mutant_problems()
    except (KeyError, ValueError) as error:
        problems.append('guard mutants: %s' % error)
    return problems


def source_checks():
    integration.profile()
    texts = production_texts()
    problems = format_violations(texts) + surface_violations() + facade_violations(texts)
    problems += guard_mutant_problems()
    # Each anchor must exist exactly once in the current sources, or this raises.
    mutant_sources()
    b0.mutants()
    admission = integration.FRAGMENTS['admission'][1].read_bytes()
    facade = (ROOT / FACADE).read_bytes()
    if facade.count(admission) != 1:
        problems.append('host admission differs from the production fragment')
    predictions = json.loads(PREDICTIONS.read_text())
    for name, expected in predictions['b1_mutants_caught_at_least'].items():
        if name not in MUTANTS or not set(expected) <= set(FOCUSED_RUNS) | set(FAULT_NAMES):
            problems.append('mutant prediction inconsistent: ' + name)
    if set(predictions['b1_mutants_caught_at_least']) != set(MUTANTS):
        problems.append('mutant predictions do not list every mutant')
    if (len(set(FOCUSED_RUNS)) != len(FOCUSED_RUNS) or len(set(FAULT_NAMES)) != len(FAULT_NAMES)
            or len(set(DEFAULT_NAMES)) != len(DEFAULT_NAMES)):
        problems.append('duplicate check names')
    problems += twin_problems(predictions)
    problems += label_problems()
    for revision in REVISIONS:
        if set(BASELINE_SHA256.get(revision, ())) != set(ARCHIVED_FRAMEWORK) | {'Settings'}:
            problems.append('baseline pins incomplete: ' + revision)
    problems += archive_problems()
    problems += boundary_problems()
    problems += floor_problems()
    return problems


# ---------------------------------------------------------------- JVM builds, guarded

def git_bytes(revision, path):
    _LOADER.append(True)
    try:
        result = subprocess.run(['git', '-C', str(ROOT), 'show', '%s:%s' % (revision, path)],
                                capture_output=True, timeout=60,
                                env=dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1'))
    finally:
        _LOADER.pop()
    if result.returncode:
        raise ValueError('baseline source unavailable: ' + path)
    return result.stdout


def git_paths(revision, directory):
    _LOADER.append(True)
    try:
        result = subprocess.run(['git', '-C', str(ROOT), 'ls-tree', '-r', '--name-only', revision,
                                 directory], capture_output=True, timeout=60,
                                env=dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1'))
    finally:
        _LOADER.pop()
    if result.returncode:
        raise ValueError('baseline tree unavailable: ' + directory)
    return sorted(result.stdout.decode().splitlines())


def tool_environment():
    """The environment of every compiler and JVM the runners start: theirs, without CLASSPATH. Each
    starts in its own work directory, so neither an inherited class path nor the repository as a
    default class or source path reaches it."""
    return {name: value for name, value in os.environ.items() if name != 'CLASSPATH'}


def product_sources(framework_override=None):
    """The current framework sources, guarded fixtures and host facades, as relative source path to
    bytes, with an optional override of framework sources."""
    files = {}
    for name in FRAMEWORK:
        files['framework/%s.java' % name] = (ROOT / FRAMEWORK_DIR / (name + '.java')).read_bytes()
    for name in ('AppIdSettingMap', 'ResilientAtomicFile'):
        files['fixtures/%s.java' % name] = (ROOT / PLATFORM / (name + '.java.inc')).read_bytes()
    stubs = {}
    for directory in STUB_DIRECTORIES:
        prefix = PLATFORM + directory + '/'
        for path in sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / prefix).rglob('*.java')):
            relative = path[len(prefix):]
            if relative.endswith('/Xml.java'):
                continue
            if relative in stubs and relative != 'android/util/Log.java':
                raise ValueError('unreviewed host facade overlap: ' + relative)
            stubs[relative] = (ROOT / path).read_bytes()
    for relative, data in stubs.items():
        files['stubs/' + relative] = data
    for name, text in (framework_override or {}).items():
        files['framework/%s.java' % name] = text.encode()
    return files


def store_sources():
    """The records, store, strict writer and file facades alone, as the store suites compile."""
    files = {'framework/%s.java' % name: (ROOT / FRAMEWORK_DIR / (name + '.java')).read_bytes()
             for name in ('NativeIdentityRecords', 'NativeIdentityStore')}
    files['fixtures/ResilientAtomicFile.java'] = (ROOT / PLATFORM / 'ResilientAtomicFile.java.inc').read_bytes()
    base = ROOT / PLATFORM / 'native_principal_xml_stubs'
    for path in sorted(base.rglob('*.java')):
        if path.name != 'Xml.java':
            files['stubs/' + path.relative_to(base).as_posix()] = path.read_bytes()
    return files


def with_seams(files):
    files = dict(files)
    files['framework/NativeIdentityStore.java'] = b0.inject(
        files['framework/NativeIdentityStore.java'].decode(), b0.STORE_SEAMS).encode()
    files['fixtures/ResilientAtomicFile.java'] = b0.inject(
        files['fixtures/ResilientAtomicFile.java'].decode(), b0.WRITER_SEAMS).encode()
    return files


def test_sources(names, adapter=None):
    """Current host tests with direct current APIs, never a selectable historical adapter."""
    files = {'tests/%s.java' % name: (ROOT / PLATFORM / (name + '.java')).read_bytes() for name in names}
    if adapter is not None:
        raise ValueError('current header tests use direct APIs, not a historical adapter')
    return files


def build(work, files):
    source = work / 'src'
    for relative, data in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    classes = work / 'classes'
    classes.mkdir(parents=True)
    result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                             '-implicit:none', '-proc:none',
                             '-d', str(classes), *sorted(str(source / name) for name in files)],
                            capture_output=True, text=True, timeout=300, cwd=work, env=tool_environment())
    return {'returncode': result.returncode, 'output': result.stdout + result.stderr,
            'stdout': result.stdout, 'stderr': result.stderr,
            'inputs': {name: sha(data) for name, data in sorted(files.items())}}


def execute(work, main, args, assertions=True, timeout=900):
    state = work / 'state'
    state.mkdir(exist_ok=True)
    result = subprocess.run(['java', '-Xmx256m', *(['-ea'] if assertions else []),
                             '-Djava.io.tmpdir=' + str(state), '-cp', str(work / 'classes'),
                             'com.android.server.pm.' + main, *args],
                            capture_output=True, text=True, timeout=timeout, cwd=work, env=tool_environment())
    return {'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr,
            'passed': b0.passed_checks(result.stdout),
            'failed': sorted(b0.failed_checks(result.stdout))}


def suite(work, files, main, args=None):
    work.mkdir(parents=True)
    built = build(work, files)
    record = {'build': built}
    if built['returncode']:
        # A compile failure is a harness failure, never an expected red result.
        record['compile_failure'] = True
        return record
    record['run'] = execute(work, main, [str(work / 'state')] + list(args or []))
    return record


B0_TESTS = {'focused': ('NativeHeaderTestSupport', b0.FOCUSED),
            'faults': ('NativeHeaderTestSupport', b0.FAULTS, 'NativeHeaderWriteFaults')}


def current_header_suite(work, kind):
    """The complete ported current header fence suites, using direct current APIs and formats."""
    names = B0_TESTS[kind]
    product = product_sources()
    if kind == 'faults':
        product = with_seams(product)
    return suite(work, {**product, **test_sources(names, adapter=None)}, names[1])


def b1_suite(work, kind, framework_override=None):
    product = product_sources(framework_override=framework_override)
    names = ['NativeHeaderTestSupport', 'NativeBindingTestSupport']
    if kind == 'faults':
        product = with_seams(product)
        names += ['NativeHeaderWriteFaults', 'NativeCreationBindingFaultTest']
        main = 'NativeCreationBindingFaultTest'
    else:
        names += ['NativeCreationBindingTest']
        main = 'NativeCreationBindingTest'
    return suite(work, {**product, **test_sources(names, adapter=None)}, main)


def outcome(record, names):
    """Passed and failed names of a finished suite, or why it is not a result."""
    if record.get('compile_failure'):
        return {'error': 'compile failure', 'build': record['build']}
    run = record['run']
    actual = run['passed'] + run['failed']
    unknown = sorted(set(actual) - set(names))
    return {'passed': run['passed'], 'failed': run['failed'], 'returncode': run['returncode'],
            'unknown': unknown, 'complete': len(actual) == len(names) and set(actual) == set(names),
            'build': record['build'], 'run': run}


# ---------------------------------------------------------------- the 24bfb6a archive: loader

ARCHIVED_FIXTURES = tuple(ARCHIVED_PLATFORM + name + '.java.inc' for name in ('AppIdSettingMap', 'ResilientAtomicFile'))


def archived_product_path(path):
    """Whether a repository path is a product fixture or host stub, which every pinned revision
    supplies."""
    return path in ARCHIVED_FIXTURES or any(path.startswith(ARCHIVED_PLATFORM + directory + '/')
                                            for directory in ARCHIVED_STUB_DIRECTORIES)


def manifest(revision):
    """Every pinned input that one registered revision supplies to an archived comparison, as
    repository path to the SHA-256 of its Git object. Its product is the 24bfb6a fixtures and host
    stubs with its own framework sources and facade and its recorded differences, beside its other
    archived inputs; 24bfb6a supplies every archived input."""
    if revision not in REVISIONS or revision not in BASELINE_SHA256:
        raise ValueError('unregistered archive revision: %s' % revision)
    pins = dict(ARCHIVE_SHA256) if revision == ARCHIVE else {
        path: digest for path, digest in ARCHIVE_SHA256.items() if archived_product_path(path)}
    pins.update(PRODUCT_DIFFERENCES.get(revision, {}))
    pins.update({ARCHIVED_FRAMEWORK_DIR + name + '.java': BASELINE_SHA256[revision][name]
                 for name in ARCHIVED_FRAMEWORK})
    pins[ARCHIVED_FACADE] = BASELINE_SHA256[revision]['Settings']
    pins.update(BASELINE_INPUTS_SHA256.get(revision, {}))
    return pins


def pinned_bytes(revision, path):
    """One archived input: the Git object at a registered revision, refused unless the manifest
    pins that path and the object's SHA-256 is the pinned one. The one loader of every archived
    comparison."""
    digest = manifest(revision).get(path)
    if digest is None:
        raise ValueError('unpinned archived input: %s %s' % (revision, path))
    data = git_bytes(REVISIONS[revision], path)
    if sha(data) != digest:
        raise ValueError('archived input drift: %s %s' % (revision, path))
    return data


def pinned_paths(revision, directory):
    """The pinned inputs below one directory of a registered revision, refused unless they are
    exactly its Git tree there, the unused XML stub aside."""
    pinned = sorted(path for path in manifest(revision) if path.startswith(directory))
    tree = [path for path in git_paths(REVISIONS[revision], directory) if not path.endswith('/Xml.java')]
    if pinned != tree:
        raise ValueError('archived tree drift: %s %s' % (revision, directory))
    return pinned


class WorktreeRead(RuntimeError):
    """A path read under the repository root while an archived assembly runs. It is no OSError,
    so no handler of file errors can take it for a missing file."""


# The tree an archived assembly closes: the repository root.
CLOSED_ROOT = ROOT
# The audit events of path reads: opening a file, which pathlib's reads do too, listing a
# directory and globbing. Git objects are read by a git subprocess, which raises none of these.
READ_EVENTS = frozenset({'open', 'os.listdir', 'os.scandir', 'glob.glob', 'glob.glob/2',
                         'pathlib.Path.glob', 'pathlib.Path.rglob'})
# The audit events of process starts. A sealed assembly starts a process only through the Git reader,
# git_bytes and git_paths, which mark their own subprocess as the loader's.
SPAWN_EVENTS = frozenset({'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.spawn', 'os.fork',
                          'os.forkpty', 'pty.spawn'})
_CLOSED = []
_SEALED = []
_LOADER = []


def _refuse_worktree_reads(event, args):
    """While the working tree is closed, refuse each path read under the repository root. While an
    assembly is also sealed, refuse every process start outside the Git reader and every path read
    outside the repository too."""
    if not _CLOSED:
        return
    if _SEALED and not _LOADER:
        if event in SPAWN_EVENTS:
            raise WorktreeRead('sealed assembly started a process outside the Git reader: ' + event)
        if event in READ_EVENTS and not (args and isinstance(args[0], int)):
            raise WorktreeRead('sealed assembly read a path: %r' % (args[0] if args else None,))
    if event not in READ_EVENTS or not args or isinstance(args[0], int):
        return
    try:
        path = os.path.realpath(os.path.abspath(os.fsdecode(args[0])))
    except (TypeError, ValueError):
        return
    root = os.path.realpath(CLOSED_ROOT)
    if path == root or path.startswith(root + os.sep):
        raise WorktreeRead('archived assembly read the working tree: ' + path)


sys.addaudithook(_refuse_worktree_reads)


@contextlib.contextmanager
def worktree_closed():
    """Close the working tree: while active, opening, listing or globbing any path under the
    repository root raises WorktreeRead."""
    _CLOSED.append(True)
    try:
        yield
    finally:
        _CLOSED.pop()


def archived(assembly):
    """An archived assembly: it runs with the working tree closed, so it can read pinned Git
    objects only."""
    @functools.wraps(assembly)
    def closed(*args, **kwargs):
        with worktree_closed():
            return assembly(*args, **kwargs)
    return closed


def _sealed_stat(original):
    """A path examination that a sealed assembly refuses outside the Git reader. No audit event
    reports a stat, an access check or a link read, so os.stat, os.lstat, os.access and os.readlink are
    wrapped while the assembly runs; pathlib and os.path reach them."""
    @functools.wraps(original)
    def guarded(path, *args, **kwargs):
        if _SEALED and not _LOADER:
            raise WorktreeRead('sealed assembly examined a path: %r' % (path,))
        return original(path, *args, **kwargs)
    return guarded


def sealed(assembly):
    """A sealed archived assembly: the working tree is closed, and it starts no process and reads,
    lists or examines no path outside the repository either. Its only input is the Git objects that
    git_bytes and git_paths read, so its manifest names everything it read."""
    @functools.wraps(assembly)
    def closed(*args, **kwargs):
        with worktree_closed():
            _SEALED.append(True)
            stat, lstat, access, readlink = os.stat, os.lstat, os.access, os.readlink
            os.stat, os.lstat = _sealed_stat(stat), _sealed_stat(lstat)
            os.access, os.readlink = _sealed_stat(access), _sealed_stat(readlink)
            try:
                return assembly(*args, **kwargs)
            finally:
                os.stat, os.lstat, os.access, os.readlink = stat, lstat, access, readlink
                _SEALED.pop()
    return closed


def outside_repository(path):
    """Whether a path resolves outside the repository, where archived scratch work may be written."""
    resolved, root = Path(path).resolve(), Path(CLOSED_ROOT).resolve()
    return resolved != root and root not in resolved.parents


def archived_tool_environment():
    """The environment of every archived compiler and JVM: the runner's, without CLASSPATH."""
    return {name: value for name, value in os.environ.items() if name != 'CLASSPATH'}


@archived
def archived_predictions(runner):
    """The predictions one runner stated at 24bfb6a, from their pinned Git object: binding, history
    or counter."""
    return json.loads(pinned_bytes(ARCHIVE, ARCHIVED_PREDICTIONS[runner]))


def archived_distinct(names, count):
    """Whether a name list holds exactly count names, none repeated."""
    return len(names) == len(set(names)) == count


# ---------------------------------------------------------------- the 24bfb6a archive: copied code
# The 24bfb6a functions the archive runs, copied verbatim but for their names and, where marked,
# reading pinned objects, the hardened tool start of build and execute, and their frozen
# constants. The archive calls no living function of the three runners. Tests compare each copy
# with its 24bfb6a Git object.

def archived_replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('creation binding source seam drift: ' + old[:80])
    return text.replace(old, new, 1)


def archived_strip_java_comments(text):
    """Java text with comments blanked, string and character literals kept."""
    result, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = n - 2 if end < 0 else end
            result.append(' ' * (end + 2 - i))
            i = end + 2
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == '\\' else 1
            result.append(text[i:j + 1])
            i = j + 1
        else:
            result.append(c)
            i += 1
    return ''.join(result)


def archived_r0_forward(text):
    """The text with the earlier images' boot literal Format.V1 replaced by Format.V2: the whole R0
    change of the native patch and of the adapted Settings, and the code change of the host
    facade's default. None unless exactly one earlier literal and no production literal occur.
    Historical comparisons use it to allow exactly that change and nothing else."""
    old, new = ARCHIVED_RETIRED + ');', ARCHIVED_PRODUCTION + ');'
    if text.count(old) != 1 or text.count(new):
        return None
    return text.replace(old, new, 1)


def archived_passed_checks(stdout):
    return re.findall(r'^PASS (.+)$', stdout, re.M)


def archived_failed_checks(stdout):
    return set(re.findall(r'^FAIL (.+?): ', stdout, re.M))


def archived_inject(text, seams):
    for anchor, position, indent, step, expression in seams:
        call = ' ' * indent + 'NativeHeaderWriteFaults.at("%s", %s);\n' % (step, expression)
        text = archived_replace_once(text, anchor, call + anchor if position == 'before' else anchor + call)
    return text


def archived_with_seams(files):
    files = dict(files)
    files['framework/NativeIdentityStore.java'] = archived_inject(
        files['framework/NativeIdentityStore.java'].decode(), ARCHIVED_STORE_SEAMS).encode()
    files['fixtures/ResilientAtomicFile.java'] = archived_inject(
        files['fixtures/ResilientAtomicFile.java'].decode(), ARCHIVED_WRITER_SEAMS).encode()
    return files


def archived_build(work, files):
    source = work / 'src'
    for relative, data in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    classes = work / 'classes'
    classes.mkdir(parents=True)
    result = subprocess.run(['javac', '-J-Xmx256m', '--release', '17', '-Xlint:all', '-Werror',
                             '-implicit:none', '-proc:none',
                             '-d', str(classes), *sorted(str(source / name) for name in files)],
                            capture_output=True, text=True, timeout=300, cwd=work, env=archived_tool_environment())
    return {'returncode': result.returncode, 'output': result.stdout + result.stderr,
            'stdout': result.stdout, 'stderr': result.stderr,
            'inputs': {name: sha(data) for name, data in sorted(files.items())}}


def archived_execute(work, main, args, assertions=True, timeout=900):
    state = work / 'state'
    state.mkdir(exist_ok=True)
    result = subprocess.run(['java', '-Xmx256m', *(['-ea'] if assertions else []),
                             '-Djava.io.tmpdir=' + str(state), '-cp', str(work / 'classes'),
                             'com.android.server.pm.' + main, *args],
                            capture_output=True, text=True, timeout=timeout, cwd=work, env=archived_tool_environment())
    return {'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr,
            'passed': archived_passed_checks(result.stdout),
            'failed': sorted(archived_failed_checks(result.stdout))}


def archived_suite(work, files, main, args=None):
    work.mkdir(parents=True)
    built = archived_build(work, files)
    record = {'build': built}
    if built['returncode']:
        # A compile failure is a harness failure, never an expected red result.
        record['compile_failure'] = True
        return record
    record['run'] = archived_execute(work, main, [str(work / 'state')] + list(args or []))
    return record


def archived_outcome(record, names):
    """Passed and failed names of a finished suite, or why it is not a result."""
    if record.get('compile_failure'):
        return {'error': 'compile failure', 'build': record['build']}
    run = record['run']
    actual = run['passed'] + run['failed']
    unknown = sorted(set(actual) - set(names))
    return {'passed': run['passed'], 'failed': run['failed'], 'returncode': run['returncode'],
            'unknown': unknown, 'complete': len(actual) == len(names) and set(actual) == set(names),
            'build': record['build'], 'run': run}


def archived_class_differences(first, second):
    """Class files that differ between two output trees, or exist in only one of them. Pure."""
    trees = [{path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*.class')}
             for root in (first, second)]
    return sorted(name for name in set(trees[0]) | set(trees[1]) if trees[0].get(name) != trees[1].get(name))


def archived_copy_layouts(layouts):
    """How many emitted layouts record a version 2 header copy as their kind."""
    return sum((layout / 'kind').read_text() == 'copy\n' for layout in sorted(layouts.iterdir()))


def archived_rollback_names(prefix, layouts, controls):
    """The case names one rollback check prints: each layout, each control and the copy count."""
    return sorted(['%s / %s' % (prefix, name) for name in layouts] + ['%s / version 2 copy layouts' % prefix]
                  + ['%s control / %s' % (prefix, name) for name in controls])


# ---------------------------------------------------------------- the 24bfb6a archive: assemblies

def archived_product_sources(revision):
    """The framework sources, guarded fixtures and host facades of one registered revision, as
    relative source path to bytes, exactly from its pinned Git objects."""
    files = {}
    for name in ARCHIVED_FRAMEWORK:
        files['framework/%s.java' % name] = pinned_bytes(revision, ARCHIVED_FRAMEWORK_DIR + name + '.java')
    for name in ('AppIdSettingMap', 'ResilientAtomicFile'):
        files['fixtures/%s.java' % name] = pinned_bytes(revision, ARCHIVED_PLATFORM + name + '.java.inc')
    stubs = {}
    for directory in ARCHIVED_STUB_DIRECTORIES:
        prefix = ARCHIVED_PLATFORM + directory + '/'
        for path in pinned_paths(revision, prefix):
            relative = path[len(prefix):]
            if relative in stubs and relative != 'android/util/Log.java':
                raise ValueError('unreviewed host facade overlap: ' + relative)
            stubs[relative] = pinned_bytes(revision, path)
    for relative, data in stubs.items():
        files['stubs/' + relative] = data
    return files


def archived_test_sources(names, adapter=None, revision=ARCHIVE):
    """Host test sources and an optional NativeHeaderApi adapter of one registered revision, exactly
    from its pinned Git objects."""
    files = {'tests/%s.java' % name: pinned_bytes(revision, ARCHIVED_PLATFORM + name + '.java') for name in names}
    if adapter:
        files['tests/NativeHeaderApi.java'] = pinned_bytes(
            revision, ARCHIVED_PLATFORM + 'native_header_api/%s/NativeHeaderApi.java' % adapter)
    return files


@archived
def archived_store_sources(revision):
    """The store class identity inputs: the 24bfb6a records, strict writer and file facades with
    one pinned revision's store helper."""
    prefix = ARCHIVED_PLATFORM + 'native_principal_xml_stubs/'
    files = {'framework/%s.java' % name: pinned_bytes(ARCHIVE, ARCHIVED_FRAMEWORK_DIR + name + '.java')
             for name in ('NativeIdentityRecords', 'NativeIdentityStore')}
    files['fixtures/ResilientAtomicFile.java'] = pinned_bytes(ARCHIVE,
                                                          ARCHIVED_PLATFORM + 'ResilientAtomicFile.java.inc')
    for path in pinned_paths(ARCHIVE, prefix):
        files['stubs/' + path[len(prefix):]] = pinned_bytes(ARCHIVE, path)
    files['framework/NativeIdentityStore.java'] = pinned_bytes(revision, ARCHIVED_STORE)
    return files


@archived
def archived_b0_files(baseline, kind, original):
    """One archived B0 leg over a registered revision's product, with the archived seams for its
    faults: the original suite of c9264e4, or the 24bfb6a suite through the baseline adapter on
    an older product and through the B1 adapter on 24bfb6a itself."""
    names = ARCHIVED_B0_TESTS[kind]
    product = archived_product_sources(baseline)
    if kind == 'faults':
        product = archived_with_seams(product)
    if original:
        return {**product, **archived_test_sources(names, revision='c926')}
    adapter = 'b1' if baseline == ARCHIVE else 'baseline'
    return {**product, **archived_test_sources(names, adapter=adapter)}


@archived
def archived_emitter_files():
    """The pinned 24bfb6a layout emitter on the pinned 24bfb6a product, with the archived seams."""
    return {**archived_with_seams(archived_product_sources(ARCHIVE)),
            **archived_test_sources(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHeaderWriteFaults',
                                     'NativeCreationBindingLayouts'], adapter='b1')}


@archived
def archived_reader_files(baseline, adapter):
    """One archived version 1 reader: a registered revision's product with the 24bfb6a reader
    check and adapter."""
    return {**archived_product_sources(baseline),
            **archived_test_sources(['NativeHeaderTestSupport', 'NativeCreationBindingReaderCheck'], adapter=adapter)}


@archived
def archived_rollback_files(baseline):
    """One archived facade rollback check: a registered revision's product with the 24bfb6a check."""
    return {**archived_product_sources(baseline),
            **archived_test_sources(['NativeHeaderTestSupport', 'NativeRollbackReaderCheck'], adapter='b1')}


def archived_reader_baseline(target):
    """The registered revision one archived reader target reads."""
    return {name: baseline for name, baseline, _ in ARCHIVED_READERS}[target]


@archived
def archived_inputs():
    """Every archived input set of this runner, by leg, assembled with the working tree closed."""
    legs = {'store classes ' + revision: archived_store_sources(revision) for revision in (ARCHIVE, '7845')}
    for baseline in ('c926', 'd104', ARCHIVE):
        for kind in ARCHIVED_B0_TESTS:
            for original in ((True, False) if baseline != ARCHIVE else (False,)):
                leg = 'b0 %s %s %s' % (baseline, kind, 'original' if original else 'adapted')
                legs[leg] = archived_b0_files(baseline, kind, original)
    legs['emitter'] = archived_emitter_files()
    for target, baseline, adapter in ARCHIVED_READERS:
        legs['reader ' + target] = archived_reader_files(baseline, adapter)
    for target in ARCHIVED_ROLLBACK_READERS:
        legs['rollback ' + target] = archived_rollback_files(archived_reader_baseline(target))
    return legs


# ---------------------------------------------------------------- the 24bfb6a archive: runs

def archived_store_class_identity(work):
    """R0 changed only comments of the store helper. Compiled with the same pinned 24bfb6a records,
    strict writer and facades, the pinned 24bfb6a and 78456b3 helpers give identical class files.
    Guarded."""
    record = {'differences': None}
    for name in (ARCHIVE, '7845'):
        (work / name).mkdir(parents=True)
        record[name] = archived_build(work / name, archived_store_sources(name))
        if record[name]['returncode']:
            return record
    record['differences'] = archived_class_differences(work / ARCHIVE / 'classes', work / '7845/classes')
    record['classes'] = len(list((work / ARCHIVE / 'classes').rglob('*.class')))
    return record


def archived_b0_suite(work, baseline, kind, original):
    """One archived B0 leg, over pinned Git objects only."""
    return archived_suite(work, archived_b0_files(baseline, kind, original), ARCHIVED_B0_TESTS[kind][1])


def archived_qualify(work):
    """Every archived step of this runner, with its problems: the store class identity, the B0
    legs over the pinned c9264e4, d104e15 and 24bfb6a products, and the R0 layout pipeline of the
    pinned 24bfb6a emitter, each as R0 ran it, with the pinned 24bfb6a predictions. Guarded: the
    caller has passed resource_guard."""
    predictions = archived_predictions('binding')
    steps, problems = {}, []

    # The store helper's R0 comment change: class files identical to the 78456b3 helper's.
    steps['store classes'] = archived_store_class_identity(work / 'store-classes')
    if steps['store classes']['differences'] != [] or not steps['store classes'].get('classes'):
        problems.append('store helper class files differ from 78456b3: %s' % steps['store classes']['differences'])

    # The archived suite, unchanged, then the adapted suite through each adapter.
    for baseline in ('c926', 'd104'):
        for kind, names in (('focused', ARCHIVED_B0_FOCUSED_NAMES), ('faults', ARCHIVED_B0_FAULT_NAMES)):
            original = archived_outcome(archived_b0_suite(
                work / ('b0-original-%s-%s' % (baseline, kind)), baseline, kind, True), names)
            adapted = archived_outcome(archived_b0_suite(
                work / ('b0-adapted-%s-%s' % (baseline, kind)), baseline, kind, False), names)
            steps['b0 %s %s' % (baseline, kind)] = {'original': original, 'adapted': adapted}
            if 'error' in original or 'error' in adapted:
                problems.append('b0 %s %s did not compile' % (baseline, kind))
                continue
            if original['failed'] != adapted['failed'] or original['passed'] != adapted['passed']:
                problems.append('b0 %s %s adapted suite differs from the archived suite' % (baseline, kind))
            if not (original['complete'] and adapted['complete']):
                problems.append('b0 %s %s incomplete' % (baseline, kind))
            expected = (predictions['b0_adapted_suite']['d104e15']['focused_failures' if kind == 'focused'
                        else 'fault_failures'] if baseline == 'd104' else [])
            # Reported separately: the archived suite's own failures are the requirement.
            matches = sorted(expected) == adapted['failed']
            steps['b0 %s %s' % (baseline, kind)]['prediction_matches'] = matches
            if not matches:
                problems.append('b0 %s %s exact failure set differs' % (baseline, kind))
            for label, result in (('original', original), ('adapted', adapted)):
                if result['returncode'] != (1 if expected else 0):
                    problems.append('b0 %s %s %s exit status' % (baseline, kind, label))
            count = {'focused': 41, 'faults': 18}[kind] if baseline == 'd104' else 0
            if len(adapted['failed']) != count:
                problems.append('b0 %s %s failed %d, expected %d' % (baseline, kind, len(adapted['failed']), count))
    # The adapted suite on the pinned 24bfb6a sources through the B1 adapter, as the b1-v1 leg ran it
    # when those were the current sources: every case passes, in order.
    for kind, names in (('focused', ARCHIVED_B0_FOCUSED_NAMES), ('faults', ARCHIVED_B0_FAULT_NAMES)):
        adapted = archived_outcome(archived_b0_suite(work / ('b0-adapted-24bf-' + kind), ARCHIVE, kind, False), names)
        steps['b0 24bf ' + kind] = {'adapted': adapted}
        if ('error' in adapted or adapted['failed'] or adapted['passed'] != list(names)
                or adapted['returncode'] != 0):
            problems.append('b0 adapted suite on 24bfb6a ' + kind)

    # Version 2 layouts from the pinned 24bfb6a production writer, read by the version 1 rollback
    # reader, its 24bf-v1 twin and the pinned 78456b3 image, and by archived c9264e4.
    emitter = work / 'archived-layouts-emitter'
    emitter.mkdir(parents=True)
    built = archived_build(emitter, archived_emitter_files())
    layouts = work / 'archived-layouts'
    if built['returncode']:
        problems.append('archived layout emitter did not compile')
        steps['archived readers'] = {'emitter_build': built['output']}
        return steps, problems
    emitted = archived_execute(emitter, 'NativeCreationBindingLayouts', [str(layouts), str(emitter / 'state')])
    names = sorted(p.name for p in layouts.iterdir()) if layouts.is_dir() else []
    steps['archived readers'] = {'emitted': names, 'emitter_returncode': emitted['returncode'],
                                 'emitter_build': built, 'emitter_run': emitted}
    if emitted['returncode'] or tuple(names) != ARCHIVED_LAYOUT_NAMES:
        problems.append('archived layout emitter')
    steps['archived readers']['copy_layouts'] = archived_copy_layouts(layouts) if layouts.is_dir() else None
    if steps['archived readers']['copy_layouts'] != ARCHIVED_COPY_LAYOUTS:
        problems.append('archived version 2 copy layouts %s, not the predicted %d'
                        % (steps['archived readers']['copy_layouts'], ARCHIVED_COPY_LAYOUTS))
    for target, baseline, adapter in ARCHIVED_READERS:
        copy = work / ('archived-layouts-' + target)
        shutil.copytree(layouts, copy, symlinks=True)
        reader = work / ('archived-reader-' + target)
        reader.mkdir(parents=True)
        built = archived_build(reader, archived_reader_files(baseline, adapter))
        if built['returncode']:
            problems.append('archived reader %s did not compile' % target)
            steps['archived readers'][target] = {'build': built}
            continue
        run = archived_execute(reader, 'NativeCreationBindingReaderCheck', [str(copy), str(reader / 'state')])
        steps['archived readers'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                             'passed': len(run['passed']), 'build': built, 'run': run}
        if (run['returncode'] or run['failed'] or run['passed'] !=
                ['version 1 reader / ' + name for name in ARCHIVED_LAYOUT_NAMES]):
            problems.append('archived reader ' + target)
    # The rollback effects in the Settings facade: no history, holds without pins and every mapped
    # native package kept but refused by the scan.
    steps['archived rollback'] = {}
    for target in ARCHIVED_ROLLBACK_READERS:
        copy = work / ('archived-layouts-rollback-' + target)
        shutil.copytree(layouts, copy, symlinks=True)
        checker = work / ('archived-rollback-' + target)
        checker.mkdir(parents=True)
        built = archived_build(checker, archived_rollback_files(archived_reader_baseline(target)))
        if built['returncode']:
            problems.append('archived rollback reader %s did not compile' % target)
            steps['archived rollback'][target] = {'build': built}
            continue
        run = archived_execute(checker, 'NativeRollbackReaderCheck', [
            str(copy), str(checker / 'state'), str(ARCHIVED_COPY_LAYOUTS), ','.join(ARCHIVED_ROLLBACK_CONTROLS)])
        steps['archived rollback'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                              'passed': len(run['passed']), 'build': built, 'run': run}
        if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                archived_rollback_names('rollback reader', ARCHIVED_LAYOUT_NAMES, ARCHIVED_ROLLBACK_CONTROLS)):
            problems.append('archived rollback reader ' + target)
    return steps, problems


@archived
def archive_problems():
    """The archive's own consistency, with the working tree closed: every pin of every registered
    revision equals its Git object, each pinned stub tree is exactly its revision's tree, the
    archived seams anchor once in each pinned store and strict writer they enter, and the frozen
    expectations are the ones the pinned 24bfb6a predictions state."""
    problems = []
    for revision in sorted(REVISIONS):
        try:
            for directory in ARCHIVED_STUB_DIRECTORIES:
                pinned_paths(revision, ARCHIVED_PLATFORM + directory + '/')
            for path in sorted(manifest(revision)):
                pinned_bytes(revision, path)
        except ValueError as error:
            problems.append('archive pins: %s' % error)
    for revision in ('c926', 'd104', ARCHIVE):
        try:
            archived_with_seams(archived_product_sources(revision))
        except ValueError as error:
            problems.append('archived seams on %s: %s' % (revision, error))
    predictions = archived_predictions('binding')
    d104 = predictions['b0_adapted_suite']['d104e15']
    if (set(d104['focused_failures']) | set(d104['focused_controls']) != set(ARCHIVED_B0_FOCUSED_NAMES)
            or set(d104['fault_failures']) | set(d104['fault_controls']) != set(ARCHIVED_B0_FAULT_NAMES)
            or not archived_distinct(ARCHIVED_B0_FOCUSED_NAMES, 53)
            or not archived_distinct(ARCHIVED_B0_FAULT_NAMES, 27)
            or (len(d104['focused_failures']), len(d104['fault_failures'])) != (41, 18)):
        problems.append('archived B0 expectations differ from the pinned predictions')
    guard = predictions['r0_format_guard']
    seed_only = guard['rollback_seed_only_layouts']
    if (set(guard['reader_layouts']) != {'b1-v1', 'c926', '7845'}
            or set(guard['reader_layouts'].values()) != {len(ARCHIVED_LAYOUT_NAMES)}
            or not archived_distinct(ARCHIVED_LAYOUT_NAMES, 47) or not set(seed_only) <= set(ARCHIVED_LAYOUT_NAMES)
            or guard['rollback_copy_layouts'] != ARCHIVED_COPY_LAYOUTS
            or ARCHIVED_COPY_LAYOUTS != len(ARCHIVED_LAYOUT_NAMES) - len(seed_only)
            or tuple(guard['rollback_controls']) != ARCHIVED_ROLLBACK_CONTROLS
            or not set(ARCHIVED_ROLLBACK_CONTROLS) <= set(ARCHIVED_LAYOUT_NAMES) - set(seed_only)
            or guard['store_class_differences_from_7845'] != []):
        problems.append('archived layout expectations differ from the pinned predictions')
    return problems


# The other module level names of this runner that its archive uses: the pinned revisions and pins,
# the Git reader, the loader, its closed tree and sealed assembly guard and the archive's own check.
# Every other name the archive uses begins with archived or ARCHIVED_, so no name that looks living
# is archive code.
ARCHIVE_SHARED = ('ARCHIVE', 'REVISIONS', 'BASELINE_SHA256', 'ORIGINAL_B0_SHA256', 'ARCHIVE_SHA256',
                  'PRODUCT_DIFFERENCES', 'BASELINE_INPUTS_SHA256', 'ROOT', 'CLOSED_ROOT', 'READ_EVENTS',
                  'SPAWN_EVENTS', '_CLOSED', '_SEALED', '_LOADER', 'WorktreeRead', 'sha', 'git_bytes', 'git_paths',
                  'manifest', 'pinned_bytes', 'pinned_paths', 'worktree_closed', 'outside_repository',
                  '_refuse_worktree_reads', 'archive_problems')


def module_names(text):
    """The module level names one Python source defines: functions, classes and assignments."""
    names = set()
    for node in ast.parse(text).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
    return names


def archive_names(text, shared):
    """The module level names of one runner's archive: archived and ARCHIVED_ names and the shared
    names it declares."""
    return {name for name in module_names(text) if name.startswith(('archived', 'ARCHIVED_')) or name in shared}


def archive_boundary(text, shared, foreign):
    """Problems of one runner's archive boundary, from its source text. Every archive function, and
    every module level statement that binds or changes archive data, uses only names of its own
    runner's archive, the archives of the runners named in foreign by their aliases, and the
    standard library; a foreign alias mapped to None is no archive and is refused. Archive data is
    an archive name of this runner or of a foreign archive, or a part of one. So the archive calls
    no living function and neither reads nor is built from a living constant, and a later package
    that changes living code cannot change it."""
    defined, allowed = module_names(text), archive_names(text, shared)
    problems = []

    def archive_data(node):
        """Whether an assignment target, or an object a call changes, is archive data."""
        while isinstance(node, (ast.Subscript, ast.Attribute)):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and foreign.get(node.value.id) and node.attr in foreign[node.value.id]):
                return True
            node = node.value
        return isinstance(node, ast.Name) and node.id in allowed

    def check(where, node):
        local = {child.arg for child in ast.walk(node) if isinstance(child, ast.arg)} | {
            child.id for child in ast.walk(node) if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)}
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id in foreign:
                names = foreign[child.value.id]
                if names is None or child.attr not in names:
                    problems.append('%s uses %s.%s' % (where, child.value.id, child.attr))
            elif (isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id not in local
                    and child.id in defined and child.id not in allowed):
                problems.append('%s uses living %s' % (where, child.id))

    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef):
            if node.name in allowed:
                check('archive function ' + node.name, node)
            continue
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            targets = [node.value.func]
        else:
            continue
        if any(archive_data(target) for target in targets):
            check('archive data ' + ', '.join(ast.unparse(target) for target in targets), node)
    return problems


def boundary_problems():
    """This runner's archive uses only archive names."""
    return archive_boundary(Path(__file__).read_text(), ARCHIVE_SHARED, {'b0': None, 'integration': None})


def qualify(work):
    """Every guarded JVM step. The caller has passed resource_guard."""
    predictions = json.loads(PREDICTIONS.read_text())
    evidence = {'java': subprocess.run(['java', '-version'], capture_output=True, text=True,
                                       timeout=60).stderr.strip(), 'steps': {}, 'problems': []}
    steps, problems = evidence['steps'], evidence['problems']

    # Archived: the store class identity, the B0 legs over the pinned c9264e4, d104e15 and 24bfb6a
    # products and the R0 layout pipeline, every one over pinned Git objects with archive code only.
    archived_steps, archived_problems = archived_qualify(work)
    steps.update(archived_steps)
    problems += archived_problems

    # Ported current header fences: direct APIs and explicit formats, not a historical adapter.
    for kind, names in (('focused', b0.FOCUSED_NAMES), ('faults', b0.FAULT_NAMES)):
        adapted = outcome(current_header_suite(work / ('current-header-' + kind), kind), names)
        steps['current header ' + kind] = {'ported': adapted}
        if ('error' in adapted or adapted['failed'] or adapted['passed'] != list(names)
                or adapted['returncode'] != 0):
            problems.append('current header fence suite ' + kind)

    # B1 focused and fault matrices: every case of the focused matrix with its production twin.
    for kind, names in (('focused', FOCUSED_RUNS), ('faults', FAULT_NAMES)):
        record = b1_suite(work / ('b1-' + kind), kind)
        result = outcome(record, names)
        steps['b1 ' + kind] = result
        if 'error' in result or result['failed'] or result['passed'] != list(names) or result['returncode']:
            problems.append('b1 %s matrix' % kind)
        elif 'unqualified' not in record['run']['stdout']:
            problems.append('b1 %s scope statement missing' % kind)
        else:
            refused = execute(work / ('b1-' + kind), record_main(kind), [str(work / ('b1-' + kind) / 'state')],
                              assertions=False, timeout=120)
            if not refused['returncode'] or '-ea' not in refused['stderr']:
                problems.append('b1 %s ran without assertions' % kind)

    # The complete presence and unavailable matrix under Format.V2, the previous format: its own
    # step, under the previous label.
    presence = work / 'presence-v2'
    files = {**store_sources(), **test_sources(['NativeIdentityPresenceTest'])}
    presence.mkdir(parents=True)
    built = build(presence, files)
    steps['presence v2'] = {'build': built}
    if built['returncode']:
        problems.append('presence V2 did not compile')
    else:
        # The special-node controls bind real Unix sockets at their actual store paths.
        # Keep that path under the kernel limit, independently of the evidence path.
        with tempfile.TemporaryDirectory(prefix='b1p-', dir='/tmp') as state:
            run = execute(presence, 'NativeIdentityPresenceTest', [state, 'V2'])
        steps['presence v2'].update(returncode=run['returncode'], failed=run['failed'],
                                    passed=len(run['passed']), run=run)
        if presence_problems(run, 'V2'):
            problems.append(presence_problems(run, 'V2'))
        # The same matrix under the lifecycle format: its own step, under the production label.
        with tempfile.TemporaryDirectory(prefix='b1p-', dir='/tmp') as state:
            run = execute(presence, 'NativeIdentityPresenceTest', [state, 'V3'])
        steps['presence v3'] = {'returncode': run['returncode'], 'failed': run['failed'],
                                'passed': len(run['passed']), 'run': run}
        if presence_problems(run, 'V3'):
            problems.append(presence_problems(run, 'V3'))

    # The facade's default against explicit Format.V3 over representative stores, with the earlier
    # formats' discrimination controls; then the default routed to each earlier format, which leaves
    # every explicitly formatted run unchanged and fails exactly the default cases here.
    record = steps['production default'] = production_default_step(work / 'production-default')
    if ('error' in record or record['failed'] or record['passed'] != list(DEFAULT_NAMES)
            or record['returncode']):
        problems.append('production default check')
    elif 'unqualified' not in record['run']['stdout']:
        problems.append('production default scope statement missing')
    else:
        refused = execute(work / 'production-default', DEFAULT_TEST,
                          [str(work / 'production-default' / 'state-da')], assertions=False, timeout=120)
        record['without_assertions'] = refused
        if not refused['returncode'] or '-ea' not in refused['stderr']:
            problems.append('production default check ran without assertions')
    record['routed'] = {}
    for format_name in ('V2', 'V1'):
        routed = record['routed'][format_name] = production_default_step(
            work / ('production-default-' + format_name), format_name)
        if ('error' in routed or not routed['complete'] or not routed['returncode']
                or sorted(routed['failed']) != sorted(default_failures())):
            problems.append('production default check with the default routed to %s' % format_name)

    # Version 2 layouts from the Format.V2 host writer on the current sources, read by the legacy
    # b1-v1 reader, the current sources under Format.V1.
    emitter = work / 'layouts-emitter'
    emitter.mkdir(parents=True)
    files = {**with_seams(product_sources()),
             **test_sources(['NativeHeaderTestSupport', 'NativeBindingTestSupport', 'NativeHeaderWriteFaults',
                             'NativeCreationBindingLayouts'], adapter=None)}
    built = build(emitter, files)
    layouts = work / 'layouts'
    if built['returncode']:
        problems.append('layout emitter did not compile')
        steps['readers'] = {'emitter_build': built['output']}
    else:
        emitted = execute(emitter, 'NativeCreationBindingLayouts', [str(layouts), str(emitter / 'state')])
        names = sorted(p.name for p in layouts.iterdir()) if layouts.is_dir() else []
        steps['readers'] = {'emitted': names, 'emitter_returncode': emitted['returncode'],
                            'emitter_build': built, 'emitter_run': emitted}
        if emitted['returncode'] or tuple(names) != LAYOUT_NAMES:
            problems.append('layout emitter')
        steps['readers']['copy_layouts'] = copy_layouts(layouts) if layouts.is_dir() else None
        if steps['readers']['copy_layouts'] != ROLLBACK_COPY_LAYOUTS:
            problems.append('version 2 copy layouts %s, not the predicted %d'
                            % (steps['readers']['copy_layouts'], ROLLBACK_COPY_LAYOUTS))
        for target, baseline, adapter in READERS:
            copy = work / ('layouts-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            reader = work / ('reader-' + target)
            reader.mkdir(parents=True)
            built = build(reader, {**product_sources(),
                                   **test_sources(['NativeHeaderTestSupport', 'NativeCreationBindingReaderCheck'],
                                                  adapter=adapter)})
            if built['returncode']:
                problems.append('reader %s did not compile' % target)
                steps['readers'][target] = {'build': built}
                continue
            run = execute(reader, 'NativeCreationBindingReaderCheck', [str(copy), str(reader / 'state')])
            steps['readers'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                        'passed': len(run['passed']), 'build': built, 'run': run}
            if (run['returncode'] or run['failed'] or run['passed'] !=
                    ['version 1 reader / ' + name for name in LAYOUT_NAMES]):
                problems.append('reader ' + target)
        # The legacy rollback effects in the Settings facade: no history, holds without pins and
        # every mapped native package kept but refused by the scan.
        steps['rollback'] = {}
        for target in LEGACY_ROLLBACK:
            copy = work / ('layouts-rollback-' + target)
            shutil.copytree(layouts, copy, symlinks=True)
            checker = work / ('rollback-' + target)
            checker.mkdir(parents=True)
            built = build(checker, {**product_sources(),
                                    **test_sources(['NativeHeaderTestSupport', 'NativeRollbackReaderCheck'],
                                                   adapter=None)})
            if built['returncode']:
                problems.append('rollback reader %s did not compile' % target)
                steps['rollback'][target] = {'build': built}
                continue
            run = execute(checker, 'NativeRollbackReaderCheck', [str(copy), str(checker / 'state'),
                                                                 str(ROLLBACK_COPY_LAYOUTS), ','.join(ROLLBACK_CONTROLS)])
            steps['rollback'][target] = {'returncode': run['returncode'], 'failed': run['failed'],
                                         'passed': len(run['passed']), 'build': built, 'run': run}
            if (run['returncode'] or run['failed'] or sorted(run['passed']) !=
                    rollback_names('rollback reader', LAYOUT_NAMES, ROLLBACK_CONTROLS)):
                problems.append('rollback reader ' + target)

    # Deliberate B1 defects must compile and be caught.
    steps['mutants'] = {}
    expectations = predictions['b1_mutants_caught_at_least']
    for name, (path, text, suites) in mutant_sources().items():
        override = {Path(path).stem: text}
        failed, record = set(), {}
        for kind in suites:
            result = outcome(b1_suite(work / 'mutants' / name / kind, kind, override),
                             FOCUSED_RUNS if kind == 'focused' else FAULT_NAMES)
            record[kind] = result
            if 'error' in result:
                problems.append('mutant %s did not compile; not a red result' % name)
                continue
            failed |= set(result['failed'])
            if result['failed'] and not result['returncode']:
                problems.append('mutant %s failures did not fail the run' % name)
        missed = sorted(set(expectations[name]) - failed)
        record['missed'] = missed
        record['failed'] = sorted(failed)
        steps['mutants'][name] = record
        if missed or not failed:
            problems.append('mutant %s not caught: %s' % (name, missed))
        # A production format regression leaves every run under an earlier format passing.
        if name in PRODUCTION_MUTANTS and not failed <= set(PRODUCTION_TWINS):
            problems.append('production mutant %s failed a run under an earlier format: %s'
                            % (name, sorted(failed - set(PRODUCTION_TWINS))[:5]))
    evidence['labels'] = {step: list(step_labels(step)) for step in steps}
    evidence['reader_labels'] = dict(READER_LABELS)
    return evidence


def record_main(kind):
    return 'NativeCreationBindingFaultTest' if kind == 'faults' else 'NativeCreationBindingTest'


REGRESSIONS = (
    ('scripts/proof/tests', 'test_native_identity_store.py'),
    ('scripts/proof/tests', 'test_native_identity_persistence.py'),
    ('scripts/proof/tests', 'test_native_principal_pins.py'),
    ('scripts/proof/tests', 'test_native_preparation_faults.py'),
    ('scripts/proof/tests', 'test_native_recovery_boot.py'),
    ('scripts/proof/tests', 'test_native_header_footprint.py'),
    ('scripts/proof/tests', 'test_native_identity_writer.py'),
    ('tests/native-identity', 'test_writer.py'),
    ('tests/native-identity', 'test_jvm.py'))


def regressions():
    results = {}
    for directory, module in REGRESSIONS:
        result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover', '-v', '-s',
                                 str(ROOT / directory), '-p', module], capture_output=True, text=True,
                                timeout=7200, cwd=ROOT)
        skipped = re.findall(r'\bskipped\b', result.stderr)
        results[module] = {'returncode': result.returncode, 'skipped': len(skipped),
                           'stdout': result.stdout, 'stderr': result.stderr}
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, help='fresh JSON path outside the repository')
    parser.add_argument('--verify-candidate', type=Path,
                        help='pinned canonical framework copies; pure patch reproduction only')
    parser.add_argument('--source-checks-only', action='store_true')
    parser.add_argument('--format-guard-only', action='store_true',
                        help='the production format guard alone, over the selected base')
    args = parser.parse_args()
    report = {'runtime_qualified': False, 'android_qualified': False, 'activation': False}
    if args.format_guard_only:
        problems = format_guard()
        report.update(base=integration.BASE.release, production_patches=PRODUCTION_PATCHES,
                      format_guard=problems or 'PASS', status='FAIL' if problems else 'SOURCE_ONLY')
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    problems = source_checks()
    report['source_checks'] = problems or 'PASS'
    if args.verify_candidate:
        pinned = args.verify_candidate.resolve(strict=True)
        report['candidate'] = verify_candidate(pinned)
        if not all(row['candidate'] for row in report['candidate'].values()):
            problems.append('regenerated candidate differs from the profile')
        # B2 against B1's floor, rebuilt from the same copies with its patch from Git objects.
        report['floor'], floor = floor_forward(pinned)
        problems += floor
    if args.source_checks_only or args.verify_candidate:
        report['status'] = 'FAIL' if problems else 'SOURCE_ONLY'
        print(json.dumps(report, indent=2))
        return 1 if problems else 0
    if not args.evidence:
        parser.error('--evidence is required for a guarded run')
    evidence = args.evidence.resolve()
    if evidence.exists() or ROOT in evidence.parents:
        raise ValueError('fresh evidence outside the repository required')
    reason = resource_guard()
    if reason:
        report.update(status='NOT_RUN', reason=reason)
        print(json.dumps(report, indent=2))
        return 2
    if not (shutil.which('javac') and shutil.which('java')):
        report.update(status='NOT_RUN', reason='no JDK on PATH')
        print(json.dumps(report, indent=2))
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix='andrix-b1-') as directory:
            qualified = qualify(Path(directory))
        report.update(qualified)
        report['regressions'] = regressions()
        for module, result in report['regressions'].items():
            if result['returncode'] or result['skipped']:
                problems.append('regression ' + module)
        problems += qualified['problems']
    except Exception as error:
        report['exception'] = {'type': type(error).__name__, 'message': str(error)}
        if isinstance(error, subprocess.TimeoutExpired):
            report['exception'].update(command=error.cmd, timeout=error.timeout,
                                      stdout=(error.stdout.decode(errors='replace')
                                              if isinstance(error.stdout, bytes) else error.stdout or ''),
                                      stderr=(error.stderr.decode(errors='replace')
                                              if isinstance(error.stderr, bytes) else error.stderr or ''))
        problems.append('qualification did not complete')
    report['status'] = 'FAIL' if problems else 'PASS'
    report['problems'] = problems
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'problems': problems}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
