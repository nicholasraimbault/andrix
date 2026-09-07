/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.server.net.ct;

/** Class holding the constants used by the CT feature. */
final class Config {

    static final String TAG = "CertificateTransparency";
    static final boolean DEBUG = false;

    public static final String INSTALL_COMPLETE_ACTION = "android.intent.action.INSTALL_COMPLETE";

    // CT paths
    static final String CT_ROOT_DIRECTORY_PATH = "/data/misc/keychain/ct/";
    static final String URL_PREFIX = "https://www.gstatic.com/android/certificate_transparency/";
    static final String URL_PUBLIC_KEY = URL_PREFIX + "log_list.pub";

    // Phenotype flags
    static final String NAMESPACE_NETWORK_SECURITY = "network_security";
    private static final String FLAGS_PREFIX = "CertificateTransparencyLogList__";
    static final String FLAG_SERVICE_ENABLED = FLAGS_PREFIX + "service_enabled";

    // properties
    static final String CONTENT_DOWNLOAD_ID = "content_download_id";
    static final String METADATA_DOWNLOAD_ID = "metadata_download_id";
    static final String PUBLIC_KEY_DOWNLOAD_ID = "public_key_download_id";

    // Compatibility Version v2
    static final String COMPATIBILITY_VERSION_V2 = "v2";
    static final String URL_PREFIX_V2 = URL_PREFIX + COMPATIBILITY_VERSION_V2 + "/";
    static final String URL_LOG_LIST_V2 = URL_PREFIX_V2 + "log_list.json";
    static final String URL_SIGNATURE_V2 = URL_PREFIX_V2 + "log_list.sig";

    // Compatibility Version v3
    static final String COMPATIBILITY_VERSION_V3 = "v3";
    static final String URL_PREFIX_V3 = URL_PREFIX + COMPATIBILITY_VERSION_V3 + "/";
    static final String URL_LOG_LIST_V3 = URL_PREFIX_V3 + "log_list.ctfb";
    static final String URL_SIGNATURE_V3 = URL_PREFIX_V3 + "log_list.sig";
}
