<!-- SPDX-License-Identifier: Apache-2.0 -->

# Source licensing

The stated license texts govern permissions. The source map and explanatory notes below
add no further restrictions to those licenses.

## Original Andrix implementation

The original Andrix owner control source listed in
[`LICENSES/andrix-core-files.txt`](LICENSES/andrix-core-files.txt) is licensed under
**GPL-3.0-or-later**: the GNU General Public License, version 3 or, at your option,
any later version. The [full text](LICENSES/GPL-3.0-or-later.txt) accompanies this source.

That scope includes the original native owner/work implementation, original Console and
adapter code, original platform identity and lifecycle helpers, original host deployment
and signing implementation, and the original delegated supervision implementation. The
file list is explicit; it is not a grant over every file below the same directories.

The original Andrix implementation additions in the patches listed in
[`LICENSES/andrix-core-patches.txt`](LICENSES/andrix-core-patches.txt) are also offered under
GPL-3.0-or-later. Copied upstream context, existing upstream implementations, copyrights
and notices retain their original terms. Storing a contribution in a patch or copying it
into an Android source checkout does not remove its license. These source grants do not
assert that every eventual combined platform artifact has completed dependency, notice
or distribution review.

The file headers and build license declarations identify the current source terms. The
lists are maintained when covered implementation files or patch families are added.

## Permissive original material

Original Andrix material outside those scopes remains under
[Apache-2.0](LICENSES/Apache-2.0.txt), unless a file or component specifies other terms.
This includes the public AIDL interface definitions under `owner/aidl` and
`owner/platform/aidl`, build and integration recipes, configuration and policy data,
documentation, and original test/verification tooling not explicitly listed in the core.

The AIDL definitions and their generated client bindings remain permissive so that
independent applications and clients can use the interfaces. This is not an exception
for the core's authority, validation or other implementation, and it does not imply that
every possible copied or linked client is an independent work.

## Inherited material and earlier grants

AOSP, GrapheneOS, the selected Termux terminal sources, compiler and runtime components,
GNU Make, tmux, Vanadium, Linux, firmware and other external material keep their own
licenses, copyrights, notices and exceptions. Their source and binary rights are not
created by Andrix's license index. An input being public, referenced by a build, or
approved for use by the owner is not itself redistribution permission.

The Console statically includes a library containing inherited Apache terminal code and
original GPL adapter code. Both sets of terms and applicable nested notices are retained;
the imported source is not relabeled as original Andrix work. The terminal import's
`NOTICE` preserves the pinned WcWidth origin notices identified during the audit.

Earlier valid Apache grants for Andrix code remain valid. Releasing a newer copy under
GPL does not recall those permissions, including permissions in older public copies.
Compatible Apache ingredients may participate in a GPLv3 work while retaining their
applicable conditions. This is not an alternative Apache grant for new original core
contributions released under the GPL policy.

## Programs, builds and distribution

GPL scope follows the actual covered work and its combinations, not just a repository
directory, an intermediate build target, an APK/APEX container or a process name.
Independent programs sharing an OS are not automatically one copyright program. Copied,
linked, generated and specifically coupled implementation needs its actual analysis.

Some Andrix sources enter Android services, SystemUI or native init/LMKD combinations.
The source grant above applies to the original Andrix contributions. Inherited platform
source keeps its terms. The Soong license modules record GPL and Apache ingredients for
local combinations; they do not replace the complete input and notice inventory of a
larger platform build. Generated platform notices must retain the covered contributions'
terms before those binaries are conveyed. This source licensing change is not a new
build, a binary redistribution clearance or a phone release.

A distributor must satisfy the applicable notice and source provision obligations for
what it actually conveys. A license text or an upstream URL alone is not complete
Corresponding Source. GPLv3 Installation Information is required under the license's
actual covered work, User Product and transaction conditions. It is not a universal
phone unlocking clause or an instruction to publish every private key or independent
firmware component. The practical owner installation and recovery workflow must be
established separately.

Updated source recipe hashes identify the newly licensed helper bytes. Frozen builds and
earlier runtime results keep their original source identities. Development source checks
are verification controls, not additional restrictions on recipients' license rights.

See the [licensing policy](docs/licensing.md) for the project's goals and commercial use
policy. The applicable license texts and retained component terms govern permissions.
