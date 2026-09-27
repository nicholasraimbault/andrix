# Offline permission store reader

Status: host tool with source, provenance and decision checks. Its guarded JVM checks are
defined below; record their outcome before relying on a decoded file. Nothing here is Android
runtime, ART parser or durability evidence.

`permission_store.py` reads one stored Android permission file (`access.abx` or its reserve copy)
offline. For chosen ordinary app ids it reports the raw stored `flags` integer of
`android.permission.POST_NOTIFICATIONS`. A raw file captured read only before a guest stop can
then be decoded afterwards on the host, without starting an ART process on the guest while
writeback may still be in progress.

A decoded record is what one stored file contains. It is not live permission state, grant
authority or a grant or revocation history. The stored value is not even the live value at the
time of writing in every case: see [one time permissions](#stored-schema). It does not show that
the file was durable, or that Android will read this file at the next boot. The tool never
interprets flag bits and never repairs, rewrites or grants anything.

## Pinned inputs

[`permission-store.profile.json`](permission-store.profile.json) pins every Android file the tool
compiles or cites, by exact size and SHA-256:

- Compiled unchanged: the seven sources of the `modules-utils-binary-xml` module
  (`BinaryXmlPullParser`, `BinaryXmlSerializer`, `FastDataInput`, `FastDataOutput`,
  `ModifiedUtf8`, `TypedXmlPullParser`, `TypedXmlSerializer`), the `NonNull` and `Nullable`
  sources of the host supported `framework-annotations-lib`, and the `org.xmlpull.v1` API from
  `libcore/xml`.
- Codec references, read only and never compiled: both `modules-utils` `Android.bp` files,
  `Abx.java`, `Xml.java`, the ART parser, input and serializer variants, and
  `KXmlSerializer.java`. The limits below rely on them.
- Store references, read only and never compiled: the permission service's own writer and
  reader of this file. They are `AccessCheckingService.kt`, `AccessPersistence.kt`,
  `AccessPolicy.kt`, `AppIdPermissionPolicy.kt`, `AppIdPermissionPersistence.kt`,
  `BinaryXmlSerializerExtensions.kt`, `BinaryXmlPullParserExtensions.kt`,
  `AtomicFileExtensions.kt` and `PermissionApex.kt`. The
  [stored schema](#stored-schema) below states what they establish, and read only checks assert
  each statement against their text.
- The prebuilt JDK 25, identified by its `release` metadata. Its binaries are not hashed.

The pinned `modules-utils-binary-xml` module does not declare `host_supported`, so there is no
host jar to reuse. The tool compiles the exact source bytes instead. Only two Android classes are
replaced, by compile only facades: `android.text.TextUtils` and `android.util.Base64`. Both throw
if reached. The reader reads an attribute value only after checking that its recorded type is an
integer or a string, so it cannot reach either facade. The facades emulate nothing and do not
turn a host JVM into an Android runtime.

Any byte difference, missing file or symlink in a pinned path stops the tool before it reads the
input, with `not_run` and reason `source_drift`. A change to the profile's own structure is a
tool error: `not_run` with reason `tool_error` and detail `ProfileDrift`. A new Android release
needs a new profile review. Here `source_drift` means source verification could not complete; it is
not proof that bytes changed. An unavailable `/proc/self/fd` can produce that result while checking
sources, or `refused` with `input_open_failed` while opening an input. Neither returns app results.
Git revisions are not checked here; checkout identity belongs to the
[pinned source verifier](../../scripts/proof/grapheneos_source.md).

## Stored schema

These facts come from the pinned store references:

- `AccessCheckingService` creates `AccessPolicy()` and `AccessPersistence(policy)`, and reads and
  writes its state through that persistence.
- `AccessPersistence` keeps each user's state in `access.abx` inside
  `PermissionApex.getUserDataDirectory(userId)`, the device protected data directory of the
  `com.android.permission` APEX for that user. It writes through `writeWithReserveCopy`, which
  also copies the finished file to `access.abx.reservecopy`, and reads through
  `readWithReserveCopy`, which falls back to that copy when reading the main file fails with
  anything other than `FileNotFoundException`.
- The writer and reader are the plain classes. `BinaryXmlSerializerExtensions` constructs
  `BinaryXmlSerializer()` directly and `BinaryXmlPullParserExtensions` constructs
  `BinaryXmlPullParser()` directly. Neither source uses the `Xml` factory or its ART variants.
  This tool compiles the pinned sources for those classes, including `FastDataOutput`,
  `FastDataInput` and `ModifiedUtf8`. It does not inspect the device's loaded class bytes.
- `AccessPolicy` writes one user's state as a single `access` element without attributes. It
  holds package versions, the optional default permission grant and app function pregrant
  fingerprints, then whatever each scheme policy's `serializeUserState` writes.
- `AppIdPermissionPersistence` writes the section `app-id-permissions` without attributes. Each
  app id is an `app-id` element with exactly `attributeInt("id")`, followed by one `permission`
  element per permission. Each `permission` has exactly `attributeInterned("name")` and then
  `attributeInt("flags")`, and no children.
- One time permissions: before writing, the writer clears `RUNTIME_GRANTED` from the flags of
  every permission whose flags contain `ONE_TIME` ("Never serialize one-time permissions as
  granted"). A stored value can therefore differ from the value the running service held when
  it wrote the file.
- The platform reader looks attributes up by name. It reads `id` and `flags` with
  `getAttributeIntOrThrow`, which also accepts the `int hex` attribute type and decimal strings,
  and `name` with `getAttributeValueOrThrow`. This tool accepts less: only what the pinned writer
  produces.

`AppIdPermissionPolicy` and its user state delegation to `AppIdPermissionPersistence` are also
pinned. Which build of the binary XML classes the service links is not pinned. This remains source
and host qualification, not a claim about the device's loaded class implementation.

## Reading one file

1. Intake. The final path component is captured with `O_PATH`, `O_NOFOLLOW` and `O_CLOEXEC`,
   which neither follows a symlink nor opens the object for reading. A symlink, FIFO,
   directory, device, socket or file larger than 8 MiB is refused from that capture, before any
   readable open. The captured object is then opened for reading through `/proc/self/fd/N` with
   `O_RDONLY`, `O_CLOEXEC`, `O_NOCTTY` and `O_NONBLOCK`. `O_NOFOLLOW` is not used there, because
   it would refuse that kernel link itself. Replacing the path after the capture cannot
   substitute another file. Both descriptors must name the same device and inode, and size,
   modification time and change time must not change from the capture to the end of reading.
   Parent directories resolve normally, including symlinks: only the final component is captured
   without following. The input is never written, copied to disk or echoed. The captured identity
   only keeps one read consistent; no path or inode is recorded or treated as authority. Intake
   needs Linux `O_PATH` and a mounted `/proc`.
2. Resource guard, described under [Running](#running). No javac or java process starts unless
   it passes.
3. Build. The pinned sources and facades compile unchanged in private scratch. The reader then
   compiles with every lint warning as an error.
4. Parse. The reader gives the bytes to the pinned parser one byte per read and walks every token
   with `nextToken()` up to the first `END_DOCUMENT`, then applies the end fence.
5. Result. The tool validates the reader's JSON strictly against the input hash and length and
   the requested app ids before it reports anything.

The reader subclasses the parser only through its own `obtainFastDataInput` hook, the same hook
the ART variant uses. The `FastDataInput` it returns overrides three reads. Each returns the
pinned result unchanged or refuses the whole document:

- `readByte()` records each event byte. In the pinned parser that method reads only token event
  bytes; names and values use the short, int, long and UTF readers.
- `readUTF()` checks the [string encoding](#strings).
- `readInternedUTF()` checks the [intern rule](#strings).

The overrides use only protected members of the pinned class, its buffer positions and
constants, and read no private field. A check compares the recording parser with the plain
parser token by token, including names, text, attribute names, values and every typed attribute
reading.

### Document rules

A file is accepted only when all of these hold:

- It starts with the magic and exactly one `START_DOCUMENT` event byte `0x10`. It ends with
  exactly one `END_DOCUMENT` event byte `0x11`, which is also the last byte of the file.
- Every other token is a start tag (`0x32`) or an end tag (`0x33`), the event bytes the pinned
  serializer writes. Text, CDATA, entity, whitespace, comment, processing instruction and
  doctype tokens are refused. Attribute events appear only directly after their start tag, with a
  type the serializer writes; `TYPE_NULL` is refused.
- Every string is in the writer's encoding and no string that is already interned is defined
  again, as described under [strings](#strings).
- Tags nest with matching names under exactly one root. Depth is at most 32 and one element has
  at most 64 attributes. No element or attribute name is null or empty, attribute names are
  unique per element and no interned value is null.
- The root is `access`, without attributes. It has exactly one direct child
  `app-id-permissions`, without attributes.
- Every child of that section is an `app-id` whose only attribute is `id`, typed `int`. Every
  child of an `app-id` is a `permission` whose attributes are exactly `name`, typed interned
  string, then `flags`, typed `int`, with nothing nested inside. The `int hex` type, plain
  strings, other attribute orders and other types are refused because the writer never produces
  them. The permission name is not empty.
- `app-id` values are unique in the section. Permission names are unique within each `app-id`.

Elements outside `/access/app-id-permissions` are bounded and checked only by the general rules
above. They are never extracted. The same `app-id` and `permission` names in another section,
such as a device permission section, are neither extracted nor counted as duplicates.

### Strings

The pinned writer produces every string with `FastDataOutput.writeUTF`: it declares
`ModifiedUtf8.countBytes(value, false)` bytes and writes `ModifiedUtf8.encode(value)`. The pinned
decoder is more lenient. It decodes a raw NUL byte as U+0000 and decodes overlong two and three
byte forms to the plain character, so `acces` followed by an overlong `s` reads as `access`.
Another decoder may treat such bytes differently.

The recording input therefore checks each string the pinned `readUTF` returns. The declared
length, which is what that method consumed after its two length bytes, must equal
`ModifiedUtf8.countBytes(decoded, false)`. The bytes must then equal
`ModifiedUtf8.encode(decoded)`. The byte comparison is needed: a raw NUL takes one byte where the
writer uses two, so it can offset an overlong form elsewhere and leave the length equal. Only
these two pinned routines are used; there is no second codec. The pinned parser reads plain
string values, text tokens and entity names with `readUTF`, and the pinned `readInternedUTF`
calls it through virtual dispatch for every definition, so every string is checked. A failure
is refused as `noncanonical_string`. A four byte form, which the pinned `ArtFastDataInput`
describes for the ART variants but this store's plain writer never produces, already fails in
the pinned decoder and is refused as `parser_error`.

The pinned writer interns a string with `writeInternedUTF`. It writes a definition (`0xffff`, then
the string) only for a string that is not yet interned, and interns it while its pool holds fewer
than 65535 strings. Later uses are two byte references. After the pool is full, a new string is
defined again at every use. The pinned reader keeps the same pool. The recording input mirrors
the pool rule in a set of at most 65535 strings and refuses a definition of a string that is
already interned as `duplicate_interned_string`. Repeated definitions of a string that was never
interned, which the writer produces after the pool is full, stay accepted. References are
resolved by the pinned reader alone: an unassigned reference below the table capacity yields
`null`, which the rules above refuse.

### Extraction

For each requested app id, in request order, the result is one of these states:

- `flags`: the `flags` value of `android.permission.POST_NOTIFICATIONS` under that exact `app-id`,
  as the signed 32 bit integer that the pinned `getAttributeInt` returns.
- `permission_absent`: the `app-id` entry exists without that permission.
- `app_id_absent`: there is no such `app-id` entry.

Absence is reported only for a completely accepted document. A refusal carries no per app id
results, so a parse failure can never read as absence. Requested app ids must be 1 to 64 distinct
decimal numbers from 10000 to 19999. The file itself may hold any integer app id; unrequested
entries are only checked for uniqueness. These states describe the encoded section, not whether
an app is installed. The pinned policy reads missing permission entries with a zero default; this
tool keeps absence distinct from an explicitly encoded integer and infers no current grant.

Parsing is not authentication or damage detection. Consistent substitutions can remain well
formed. The controls demonstrate a target name replaced by another name of the same length, a
flags value replaced by another integer, and a complete permission element removed cleanly. The
limit is not restricted to changes of the same length. Integrity of the stored bytes needs separate
evidence.

## End of input and parser branches

The pinned parser is lenient at the end of input. `nextToken()` catches `EOFException` and
returns `END_DOCUMENT`, so a file that stops early, even inside a name, ends normally for an
ordinary caller. After an explicit `END_DOCUMENT` it reads nothing more, so trailing bytes are
never examined. The reader adds an end fence based on that observed behavior, not on a guessed
framing:

- The input stream delivers at most one byte per read and counts every end of input it reports.
  The pinned `FastDataInput.fill` reads only until a request is satisfied, so the bytes delivered
  equal the bytes consumed, plus the one event byte peeked after a start tag.
- An `END_DOCUMENT` is accepted only when its step consumed exactly the event byte `0x11`, the
  stream never reported end of input and every byte of the file was delivered.
- The reader then asks the parser for one more token. The parser must return `END_DOCUMENT` by
  reaching the end of input itself, without a new event or byte.

| Pinned parser behavior | Reader code |
| --- | --- |
| `setInput` fails: magic missing or wrong, or no token after it | `header` |
| `setInput` tolerates a missing `START_DOCUMENT` and ignores its type bits | `missing_start_document`, `noncanonical_event` |
| End of input while peeking, while reading a name, string or value, or inside stray attributes becomes `END_DOCUMENT` | `missing_end_document` at a token boundary after the root closed, otherwise `truncated` |
| End of input in the attribute lookahead after a start tag propagates as `EOFException` | `truncated` |
| Other `IOException`: unknown token, unknown attribute type, interned reference beyond the table, malformed modified UTF-8 including four byte forms | `parser_error` |
| Entities: unknown, empty or lone `#` names raise `XmlPullParserException`, other numeric names can raise `NumberFormatException`, known names become tokens | `parser_error` or `unexpected_token` |
| Every text, CDATA, comment, processing instruction, doctype and whitespace token reads a string, whatever its type bits | `unexpected_token`, or an earlier refusal |
| A raw NUL or an overlong form decodes without error | `noncanonical_string` |
| A second definition of an interned string is interned again | `duplicate_interned_string` |
| An unassigned interned reference below the table capacity returns `null`, for a tag name, an end tag name, an attribute name or an interned value | `invalid_name`, `mismatched_end_tag`, `invalid_value` |
| Type bits of document and tag events are ignored | `noncanonical_event` |
| Attribute events outside a start tag's lookahead, including before `START_DOCUMENT` and before `END_DOCUMENT`, are discarded silently | `stray_attribute` |
| End tag names are not compared, `END_DOCUMENT` is accepted at any depth, zero or several roots are accepted | `mismatched_end_tag`, `unclosed_elements`, `no_root`, `multiple_roots` |
| Nothing is read after `END_DOCUMENT` | `trailing_bytes` |
| Attribute lookup returns the first of duplicate names | `duplicate_attribute` |
| No limit on attributes per element, depth or tokens | `attribute_bound`, `depth_bound`, 8 MiB input |
| `getAttributeInt` also parses strings; `getAttributeValue` renders other types | `attribute_encoding`, since types are checked first |

The attribute bound applies while the parser reads: the recording input stops the parse at the
66th event byte of one step. Without it, the pinned parser's attribute pool could grow to millions
of objects for an 8 MiB file. `event_accounting` and `post_end_probe` are defensive codes; they
would mean the recording disagrees with the parser, which the pinned bytes do not allow. Parser
exception messages can quote input bytes, so results name only the exception class. A refusal
raised by the recording input itself names no exception.

## Output

Each command prints one JSON object on stdout.

`decode` objects always have exactly these keys:

- `schema`: `andrix.permission-store.post-notifications.v1`.
- `result`: `parsed`, `refused` or `not_run`.
- `requested_app_ids` in request order.
- `input`: length and SHA-256 of the bytes read, or null when that binding is unavailable.
  An unexpected tool error can lose this binding even after reading, so null does not prove the
  input was never opened.
- `document` and `app_ids`: only when parsed, otherwise null. `document` counts elements,
  `app-id` entries and permission entries, not their content.
- `refusal`: stage (`intake` or `reader`), code, exception class, byte offset, token step and
  reader exit status, or null.
- `not_run`: reason (`source_root`, `source_drift`, `resource_guard`, `jdk`, `build_failed` or
  `tool_error`) and a bounded detail, or null.
- `provenance`: SHA-256 of the tool, reader, facades and profile, the source release, whether the
  pinned sources verified, the JDK release metadata and the parser class. It is null only for a
  tool error.
- `scope`: fixed statements that the record is not live permission state, grant authority, grant
  or revocation history, Android runtime parser behavior or write durability.

`check-sources` objects have exactly `schema` (`andrix.permission-store.sources.v1`), `result`
(`verified` or `not_run`), `not_run` and `provenance`, which is null only for a tool error.

Exit statuses are 0 for `parsed` or `verified`, 1 for `refused`, 2 for usage errors, 3 for
`not_run` and 4 when the result could not be written. A result exists only as one complete JSON
object on stdout with the keys above. The exit status alone is never a result. Nothing is
promised after stdout breaks, after an out of memory kill or after a forced termination; an empty
or truncated stdout means there is no result.

An unexpected ordinary exception becomes `not_run` with reason `tool_error`, in the envelope of
the command that failed, with the exception class as the only detail. If writing the result
fails, the tool exits 4 and writes only the exception class of that failure to stderr.

Build failures and compiler timeouts are `not_run` with reason `build_failed`: the document has
not reached the parser. Once the reader JVM has the document, a crash, a timeout, an exit status
other than 0 and 1, or output that fails validation is a refusal (`reader_failure`,
`reader_timeout` or `reader_output_invalid`) with no app id results. This asymmetry is
deliberate. The tool cannot tell a failure that the document provoked from an environmental one,
so it keeps the conservative refusal, which can never read as absence.

Apart from the requested integers, no content from the file appears in the output: no names,
package names or input bytes.

## Running

```
python3 tests/permission-store/permission_store.py check-sources --source-root /path/to/android
python3 tests/permission-store/permission_store.py decode --source-root /path/to/android \
    --input /path/to/private/access.abx --app-id 10123 --app-id 10124
```

`check-sources` starts no process. `decode` starts javac and java only when this process's
cgroup, or an ancestor, limits memory to 2 GiB or less, swap to 0, CPU to 2 and tasks to 256,
and both core dump limits are zero. `RLIMIT_AS` is not accepted instead. Otherwise it reports
`not_run` with reason `resource_guard`. A systemd scope with `MemoryMax=2G`, `MemorySwapMax=0`,
`CPUQuota=200%`, `TasksMax=256` and `LimitCORE=0` provides these bounds.

The JVMs get a 512 MiB heap and two processors, exit on out of memory, and disable attach and
performance data files. On a fatal error they create no core dump themselves
(`-XX:-CreateCoredumpOnCrash`), write the error report to their own captured stderr instead of a
file (`-XX:+ErrorFileToStderr`) and write no compiler replay file (`-XX:-DumpReplayDataOnError`).
The error file setting and temporary files point into private scratch, which is removed
afterwards. A fatal error report can contain heap and register contents, and so input bytes. The
tool never passes on the reader's raw stdout or stderr; for a build failure it reports the
compiler's output, and the compiler never sees the input. These settings and the zero core
limits reduce retained crash data but do not prove its absence: a kernel or host core handler, a
debugger or a forced kill before scratch removal can still retain data. `JAVA_TOOL_OPTIONS` and
similar variables are not passed on. `--jdk` selects another JDK home; its release metadata is
recorded, and `matches_profile` shows whether it is the pinned JDK. Keep captures and decoded
results with the private operating records.

## Tests

```
ANDRIX_SOURCE_ROOT=/path/to/android \
    python3 -B -m unittest discover -s tests/permission-store -p 'test_*.py' -v
```

These checks start no JDK: profile drift, facade and reader source properties, argument bounds,
intake of symlinks, FIFOs, directories, devices, sockets, oversize, missing, replaced and
changing files with every readable open recorded, strict reader output validation, the command
line envelopes for both commands, tool errors, output delivery failure, the decision flow with
every process boundary mocked, synthetic source drift and the resource guard. One delivery check
runs the tool itself as a Python process with a closed stdout pipe. With `ANDRIX_SOURCE_ROOT`,
read only checks also verify the pinned sources, the module membership, the parser branches and
string reads above, the stored schema facts and the references behind the limits below.

`JvmTests` run only inside the guard. Set `ANDRIX_REQUIRE_JVM_CHECKS=1` so that a missing guard,
source root or JDK fails instead of skipping; `ANDRIX_JDK` selects another JDK home. They compile
everything, then:

- run `PermissionStoreChecks` with `-ea` and with `-da`, requiring identical output. It writes
  synthetic documents with the pinned `BinaryXmlSerializer` and covers the sample values 24624,
  24608 and 24672 without attaching meaning to them, the absent states, the exact writer
  encodings, the bounds, every layout, event, token and entity refusal, strings on both pinned
  `readUTF` paths up to 65535 bytes, overlong access and target names, a raw NUL alone and
  offsetting an overlong form, four byte forms, duplicate intern definitions, a full intern pool
  with repeated uncached definitions and a redefinition after it, unassigned references, stray
  attributes before `START_DOCUMENT` and `END_DOCUMENT`, every proper prefix of a document, every
  single trailing byte, a second document appended, a complete target followed by a truncated or
  malformed remainder, the integrity limits and each parser leniency listed above;
- check that no class was compiled with assertions;
- decode fixture files through the reader path the tool uses, including flag extremes and
  string and encoding refusals;
- check the reader's own input bound and argument refusals; and
- run the command line end to end, including a symlink refusal and a string refusal.

Neither the reader nor its checks use Java `assert`, and no pinned compile source contains an
`assert` statement, so assertion settings cannot change a result. The `-da` run is the control.

## Limits

- Host JVM, not ART. The service runs the plain Java classes on ART; this tool runs their pinned
  sources on a host JVM. Android's `Xml.newBinaryPullParser()` returns `ArtBinaryXmlPullParser`,
  whose `ArtFastDataInput` decodes strings through native `CharsetUtils`, which is neither pinned
  nor run here. The permission service does not use it for this file, but `abx2xml` does.
- `abx2xml` provides a separate platform execution and rendering check of names and values,
  not an independent token parser or completeness check. Its ART string decoder can differ for
  strings outside the writer's encoding, which this tool refuses. It uses `Xml.copy`, which stops
  at the first `END_DOCUMENT`, and the pinned
  parser reports the end of input as one. Its text serializer comes from `XmlObjectFactory`,
  which is outside the pinned sources. If that is the pinned `KXmlSerializer`, its `endDocument`
  also closes open elements, so a truncated file could render as a closed but incomplete
  document.
- Parsing is not authentication or damage detection, as described under
  [extraction](#extraction).
- One file per run. Which of the main file, an `AtomicFile` backup or the reserve copy Android
  reads at boot, and whether any of them was durable, are separate questions.
- Stored flags are integers only. Mapping bits to grants, denials or user choices, and deciding
  whether a revocation took effect or persisted, are outside this tool. One time permissions are
  stored without `RUNTIME_GRANTED`, whatever their live state.
