    // The privileged diagnostic of this instance's cached native identity state. It reads only what
    // the instance holds: no store read, refresh or write, and no lease of any kind. Its schema
    // follows the constructed store's slot ceiling alone, 2 under the existing formats and 3 under
    // the lifecycle format. Names are standard padded Base64 of their UTF-8 bytes. A deferred name
    // or count outside its bounds, or output above its bound, gives only the unavailable envelope,
    // never a partial or substituted report.
    String nativeIdentityDumpLPr() {
        if (!nativeIdentityDumpAvailableLPr()) return "andrix-native-identities-v2\nlive_settings=false\n";
        boolean lifecycle = nativeIdentitySlotCeilingLPr() >= 2;
        String header = lifecycle ? "andrix-native-identities-v3\n" : "andrix-native-identities-v2\n";
        String unavailable = header + "observer_available=false\n";
        // One capture of each live object under the caller's lock: the current pins through their
        // accessor and the current recovery view.
        NativePrincipalPins pins = nativePrincipalPinsLPr();
        NativePrincipalRecovery recovery = mNativeRecoveryView;
        java.util.Set<String> deferred = recovery.deferredPackageNames();
        if (deferred.size() > 100000) return unavailable;
        StringBuilder text = new StringBuilder(header);
        text.append("live_settings=true\n");
        text.append("authority=not-reported\n");
        text.append("counter_known=").append(pins.hasKnownCounter()).append('\n');
        text.append("cached_header=").append(mNativeIdentityLoaded.header.status).append('\n');
        text.append("cached_enumeration_complete=").append(mNativeIdentityLoaded.enumerationComplete).append('\n');
        text.append("creation_ready=").append(nativePrincipalCreationReadyLPr()).append('\n');
        text.append("allocator_search_start=").append(mAppIds.nativeIdentitySearchStart()).append('\n');
        text.append("unidentified_code=").append(recovery.hasUnidentifiedCode()).append('\n');
        text.append("deferred_count=").append(deferred.size()).append('\n');
        java.util.Set<Integer> held = new java.util.TreeSet<>(mNativeStoreAppIds);
        held.addAll(pins.reservedAppIds());
        if (lifecycle) text.append("slot_count=").append(held.size()).append('\n');
        StringBuilder slots = new StringBuilder();
        for (int appId : held) {
            NativeIdentityStore.ReadResult<NativeIdentityRecords.Slot> slot = mNativeIdentityLoaded.slots.get(appId);
            SettingBase mapping = mAppIds.getSetting(appId);
            String name = mapping instanceof PackageSetting pkg ? pkg.getPackageName()
                    : mapping instanceof SharedUserSetting shared ? shared.getName() : "";
            if (name == null || name.length() > 255) name = "invalid";
            byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (nameBytes.length > 255) nameBytes = "invalid".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String encoded = android.util.Base64.encodeToString(nameBytes, android.util.Base64.NO_WRAP);
            String kind = mapping == null ? "empty" : mapping instanceof PackageSetting ? "package"
                    : mapping instanceof SharedUserSetting ? "shared" : "other";
            text.append("hold=").append(appId).append('\t').append(slot == null ? "MISSING" : slot.status.name())
                    .append('\t').append(pins.isAppIdPinned(appId)).append('\t').append(kind)
                    .append('\t').append(encoded).append('\n');
            if (!lifecycle) continue;
            // Positive state only from a selected VALID body of user 0 alone, or of no user. Every
            // other record, and any decoded copy or stable prefix, reports nothing.
            String version = "not-reported", state = "not-reported", suspended = "not-reported";
            if (slot != null && slot.status == NativeIdentityStore.Status.VALID && slot.value != null) {
                NativeIdentityRecords.Slot body = slot.value;
                if (body.users.isEmpty()) {
                    version = String.valueOf(body.version);
                    state = "TOMBSTONE";
                    suspended = "false";
                } else if (body.users.size() == 1 && body.users.get(0).userId == 0) {
                    NativeIdentityRecords.Lifecycle life = body.users.get(0).lifecycle;
                    version = String.valueOf(body.version);
                    state = life.state.name();
                    suspended = String.valueOf(!life.suspensions.isEmpty());
                }
            }
            slots.append("slot=").append(appId).append('\t').append(version).append('\t').append(state)
                    .append('\t').append(suspended).append('\n');
        }
        text.append(slots);
        for (String name : deferred) {
            byte[] bytes = nativeDiagnosticNameBytes(name);
            if (bytes == null) return unavailable;
            text.append("deferred=").append(android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
                    .append('\n');
            if (text.length() > 8 * 1024 * 1024) return unavailable;
        }
        if (text.length() > 8 * 1024 * 1024) return unavailable;
        return text.toString();
    }

    // A deferred name's UTF-8 bytes, or null for an empty name, one above 255 UTF-16 code units or
    // 1020 bytes, or one that is not well formed UTF-16, such as a lone surrogate.
    private static byte[] nativeDiagnosticNameBytes(String name) {
        if (name == null || name.isEmpty() || name.length() > 255) return null;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < name.length()
                    && Character.isLowSurrogate(name.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                return null;
            }
        }
        byte[] bytes = name.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return bytes.length > 1020 ? null : bytes;
    }
