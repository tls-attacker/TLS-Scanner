/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.AnsiColor;
import de.rub.nds.scanner.core.report.ColorEncoding;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.TestResultTextEncoder;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedPropertyCategory;
import java.util.HashMap;

public class DefaultPrintingScheme {

    public static PrintingScheme getDefaultPrintingScheme() {
        HashMap<TestResult, String> textEncodingMap = new HashMap<>();
        textEncodingMap.put(TestResults.CANNOT_BE_TESTED, "cannot be tested");
        textEncodingMap.put(TestResults.COULD_NOT_TEST, "could not test");
        textEncodingMap.put(TestResults.ERROR_DURING_TEST, "error");
        textEncodingMap.put(TestResults.FALSE, "false");
        textEncodingMap.put(TestResults.NOT_TESTED_YET, "not tested yet");
        textEncodingMap.put(TestResults.TIMEOUT, "timeout");
        textEncodingMap.put(TestResults.TRUE, "true");
        textEncodingMap.put(TestResults.UNCERTAIN, "uncertain");
        textEncodingMap.put(TestResults.UNSUPPORTED, "unsupported by tls-scanner");
        textEncodingMap.put(TestResults.PARTIALLY, "partially");

        HashMap<TestResult, AnsiColor> ansiColorMap = new HashMap<>();
        ansiColorMap.put(TestResults.COULD_NOT_TEST, AnsiColor.BLUE);
        ansiColorMap.put(TestResults.ERROR_DURING_TEST, AnsiColor.RED_BACKGROUND);
        ansiColorMap.put(TestResults.UNASSIGNED_ERROR, AnsiColor.RED_BACKGROUND);
        ansiColorMap.put(TestResults.FALSE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResults.NOT_TESTED_YET, AnsiColor.WHITE);
        ansiColorMap.put(TestResults.TIMEOUT, AnsiColor.PURPLE_BACKGROUND);
        ansiColorMap.put(TestResults.TRUE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResults.UNCERTAIN, AnsiColor.YELLOW_BACKGROUND);
        ansiColorMap.put(TestResults.UNSUPPORTED, AnsiColor.CYAN);

        HashMap<TestResult, String> attackEncodingMap = new HashMap<>();
        attackEncodingMap.put(TestResults.COULD_NOT_TEST, "could not test (not vulnerable)");
        attackEncodingMap.put(TestResults.ERROR_DURING_TEST, "error");
        attackEncodingMap.put(TestResults.FALSE, "not vulnerable");
        attackEncodingMap.put(TestResults.NOT_TESTED_YET, "not tested yet");
        attackEncodingMap.put(TestResults.TIMEOUT, "timeout");
        attackEncodingMap.put(TestResults.TRUE, "vulnerable");
        attackEncodingMap.put(TestResults.UNCERTAIN, "uncertain - requires manual testing");
        attackEncodingMap.put(TestResults.UNSUPPORTED, "unsupported by TLS-Scanner");

        HashMap<TestResult, String> freshnessMap = new HashMap<>();
        freshnessMap.put(TestResults.COULD_NOT_TEST, "could not test (no)");
        freshnessMap.put(TestResults.ERROR_DURING_TEST, "error");
        freshnessMap.put(TestResults.FALSE, "false");
        freshnessMap.put(TestResults.NOT_TESTED_YET, "not tested yet");
        freshnessMap.put(TestResults.TIMEOUT, "timeout");
        freshnessMap.put(TestResults.TRUE, "true");
        freshnessMap.put(TestResults.UNCERTAIN, "uncertain - requires manual testing");
        freshnessMap.put(TestResults.UNSUPPORTED, "unsupported by TLS-Scanner");

        ColorEncoding attacks = getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN);

        HashMap<AnalyzedProperty, ColorEncoding> colorMap = new HashMap<>();
        for (TlsAnalyzedProperty prop : TlsAnalyzedProperty.values()) {
            if (prop.getCategory() == TlsAnalyzedPropertyCategory.ATTACKS) {
                colorMap.put(prop, attacks);
            }
        }
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SSL_2,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SSL_3,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_PFS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_FORTEZZA,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_EXPORT,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ANON,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_3DES,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SEED,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_IDEA,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_RC2,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_RC4,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CBC,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_AEAD,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ONLY_PFS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_AES,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CAMELLIA,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ARIA,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CHACHA,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_RSA,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_STATIC_DH,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ECDHE,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_GOST,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SRP,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_KERBEROS,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_NEWHOPE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ECMQV,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TOKENBINDING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_MONTGOMERY_CURVES,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HTTPS,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HSTS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HPKP,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_HTTP_COMPRESSION,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.PREFERS_PFS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.ENFORCES_PFS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.ENFORCES_CS_ORDERING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));

        colorMap.put(
                TlsAnalyzedProperty.MISSES_MAC_APPDATA_CHECKS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.MISSES_MAC_FINISHED_CHECKS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.MISSES_VERIFY_DATA_CHECKS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.MISSES_GCM_CHECKS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_CERTIFICATE_ISSUES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_WEAK_RANDOMNESS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.REUSES_EC_PUBLICKEY,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.REUSES_DH_PUBLICKEY,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.REUSES_GCM_NONCES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.REQUIRES_SNI,
                getDefaultColorEncoding(AnsiColor.YELLOW, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_OCSP,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_NONCE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.NONCE_MISMATCH,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.STAPLED_RESPONSE_EXPIRED,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.MUST_STAPLE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.DEFAULT_COLOR));

        colorMap.put(
                TlsAnalyzedProperty.HAS_COOKIE_CHECKS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_PORT_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.YELLOW));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                getDefaultColorEncoding(AnsiColor.DEFAULT_COLOR, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_REORDERING,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.SENDS_RETRANSMISSIONS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));

        colorMap.put(
                TlsAnalyzedProperty.STRICT_ALPN,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.STRICT_SNI,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.ALPACA_MITIGATED,
                getDefaultColorEncoding(AnsiColor.GREEN, AnsiColor.RED));
        colorMap.put(
                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        HashMap<AnalyzedPropertyCategory, TestResultTextEncoder> textMap = new HashMap<>();
        textMap.put(
                TlsAnalyzedPropertyCategory.ATTACKS, new TestResultTextEncoder(attackEncodingMap));
        textMap.put(TlsAnalyzedPropertyCategory.FRESHNESS, new TestResultTextEncoder(freshnessMap));
        textMap.put(TlsAnalyzedPropertyCategory.FFDHE, new TestResultTextEncoder(freshnessMap));
        TestResultTextEncoder defaultTextEncoding = new TestResultTextEncoder(textEncodingMap);
        ColorEncoding defaultColorEncoding = new ColorEncoding(ansiColorMap);

        HashMap<AnalyzedProperty, TestResultTextEncoder> specialTextMap = new HashMap<>();

        specialTextMap.put(TlsAnalyzedProperty.ALPACA_MITIGATED, getAlpacaTextEncoding());

        HashMap<AnalyzedProperty, String> propertyNamesMap = new HashMap<>();
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, "SSL 2");
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, "SSL 3");
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, "TLS 1.0");
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, "TLS 1.1");
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, "TLS 1.2");
        propertyNamesMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, "TLS 1.3");

        return new PrintingScheme(
                colorMap,
                textMap,
                defaultTextEncoding,
                defaultColorEncoding,
                specialTextMap,
                new HashMap<>());
    }

    private static TestResultTextEncoder getAlpacaTextEncoding() {
        HashMap<TestResult, String> textEncodingMap = new HashMap<>();
        textEncodingMap.put(TestResults.CANNOT_BE_TESTED, "cannot be tested");
        textEncodingMap.put(TestResults.COULD_NOT_TEST, "could not test");
        textEncodingMap.put(TestResults.ERROR_DURING_TEST, "error");
        textEncodingMap.put(TestResults.FALSE, "not mitigated");
        textEncodingMap.put(TestResults.NOT_TESTED_YET, "not tested yet");
        textEncodingMap.put(TestResults.TIMEOUT, "timeout");
        textEncodingMap.put(TestResults.TRUE, "true");
        textEncodingMap.put(TestResults.UNCERTAIN, "uncertain");
        textEncodingMap.put(TestResults.UNSUPPORTED, "unsupported by tls-scanner");
        textEncodingMap.put(TestResults.PARTIALLY, "partially");
        return new TestResultTextEncoder(textEncodingMap);
    }

    private static ColorEncoding getDefaultColorEncoding(
            AnsiColor trueColor, AnsiColor falseColor) {
        HashMap<TestResult, AnsiColor> colorMap = new HashMap<>();
        colorMap.put(TestResults.CANNOT_BE_TESTED, AnsiColor.WHITE);
        colorMap.put(TestResults.COULD_NOT_TEST, AnsiColor.BLUE);
        colorMap.put(TestResults.ERROR_DURING_TEST, AnsiColor.RED_BACKGROUND);
        colorMap.put(TestResults.UNASSIGNED_ERROR, AnsiColor.RED_BACKGROUND);
        colorMap.put(TestResults.FALSE, falseColor);
        colorMap.put(TestResults.NOT_TESTED_YET, AnsiColor.WHITE);
        colorMap.put(TestResults.TIMEOUT, AnsiColor.PURPLE_BACKGROUND);
        colorMap.put(TestResults.TRUE, trueColor);
        colorMap.put(TestResults.UNCERTAIN, AnsiColor.YELLOW_BACKGROUND);
        colorMap.put(TestResults.UNSUPPORTED, AnsiColor.CYAN);
        colorMap.put(TestResults.PARTIALLY, AnsiColor.YELLOW);
        return new ColorEncoding(colorMap);
    }
}
