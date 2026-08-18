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
import de.rub.nds.scanner.core.report.ColorEncoding;
import de.rub.nds.scanner.core.report.PrintingScheme;
import de.rub.nds.scanner.core.report.TestResultTextEncoder;
import de.rub.nds.scanner.core.report.markup.SemanticMarkup;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedPropertyCategory;
import java.util.HashMap;

public class DefaultPrintingScheme {

    private DefaultPrintingScheme() {
        // Private constructor to prevent instantiation of utility class
    }

    /**
     * Creates and returns the default printing scheme for TLS scan reports.
     *
     * @return A PrintingScheme configured with default color encodings and text mappings
     */
    public static PrintingScheme getDefaultPrintingScheme() {

        ColorEncoding defaultColorEncoding =
                getDefaultColorEncoding(SemanticMarkup.NEUTRAL, SemanticMarkup.NEUTRAL);

        ColorEncoding trueBadFalseGood =
                getDefaultColorEncoding(SemanticMarkup.RESULT_BAD, SemanticMarkup.RESULT_GOOD);
        ColorEncoding trueBad =
                getDefaultColorEncoding(SemanticMarkup.RESULT_BAD, SemanticMarkup.NEUTRAL);
        ColorEncoding trueGoodFalseBad =
                getDefaultColorEncoding(SemanticMarkup.RESULT_GOOD, SemanticMarkup.RESULT_BAD);
        ColorEncoding trueGood =
                getDefaultColorEncoding(SemanticMarkup.RESULT_GOOD, SemanticMarkup.NEUTRAL);
        ColorEncoding trueMediumFalseGood =
                getDefaultColorEncoding(SemanticMarkup.RESULT_MEDIUM, SemanticMarkup.RESULT_GOOD);
        ColorEncoding trueGoodFalseMedium =
                getDefaultColorEncoding(SemanticMarkup.RESULT_GOOD, SemanticMarkup.RESULT_MEDIUM);
        ColorEncoding falseBad =
                getDefaultColorEncoding(SemanticMarkup.NEUTRAL, SemanticMarkup.RESULT_BAD);
        ColorEncoding trueMediumFalseNeutral =
                getDefaultColorEncoding(SemanticMarkup.RESULT_MEDIUM, SemanticMarkup.NEUTRAL);

        HashMap<AnalyzedProperty, ColorEncoding> colorMap = new HashMap<>();
        for (TlsAnalyzedProperty prop : TlsAnalyzedProperty.values()) {
            if (prop.getCategory() == TlsAnalyzedPropertyCategory.ATTACKS) {
                colorMap.put(prop, trueBadFalseGood);
            }
        }
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_PFS, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_EXPORT, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ANON, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_DES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_3DES, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SEED, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_IDEA, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_RC2, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_RC4, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CBC, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_AEAD, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_AES, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ARIA, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CHACHA, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_RSA, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_STATIC_DH, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ECDHE, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_GOST, trueMediumFalseNeutral);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SRP, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_KERBEROS, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ECMQV, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, trueMediumFalseNeutral);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TOKENBINDING, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_MONTGOMERY_CURVES, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, trueGood);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                trueGoodFalseBad);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT, trueGood);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, trueGoodFalseMedium);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION, trueGood);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
                trueGood);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HTTPS, defaultColorEncoding);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HSTS, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HPKP, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_HTTP_COMPRESSION, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.PREFERS_PFS, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.ENFORCES_PFS, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.ENFORCES_CS_ORDERING, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING, trueGoodFalseMedium);
        colorMap.put(
                TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING,
                trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS, trueBadFalseGood);

        colorMap.put(TlsAnalyzedProperty.MISSES_MAC_APPDATA_CHECKS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.MISSES_MAC_FINISHED_CHECKS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.MISSES_VERIFY_DATA_CHECKS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.MISSES_GCM_CHECKS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_CERTIFICATE_ISSUES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_WEAK_RANDOMNESS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.REUSES_GCM_NONCES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.REQUIRES_SNI, trueMediumFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_OCSP, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_NONCE, trueGood);
        colorMap.put(TlsAnalyzedProperty.NONCE_MISMATCH, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.STAPLED_RESPONSE_EXPIRED, trueBad);
        colorMap.put(TlsAnalyzedProperty.MUST_STAPLE, trueGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13, trueGood);

        colorMap.put(TlsAnalyzedProperty.HAS_COOKIE_CHECKS, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_PORT_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE, trueGoodFalseMedium);
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
                trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE, trueBadFalseGood);
        colorMap.put(
                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, falseBad);
        colorMap.put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, falseBad);
        colorMap.put(TlsAnalyzedProperty.SUPPORTS_REORDERING, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG, trueBadFalseGood);

        colorMap.put(TlsAnalyzedProperty.STRICT_ALPN, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.STRICT_SNI, trueGoodFalseBad);
        colorMap.put(TlsAnalyzedProperty.VULNERABLE_TO_ALPACA, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE, trueBadFalseGood);
        colorMap.put(
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                trueBadFalseGood);

        colorMap.put(TlsAnalyzedProperty.UNENCRYPTED_TICKET, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.DEFAULT_HMAC_KEY_TICKET, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.NO_MAC_CHECK_TICKET, trueBadFalseGood);
        colorMap.put(TlsAnalyzedProperty.PADDING_ORACLE_TICKET, trueBadFalseGood);
        HashMap<AnalyzedPropertyCategory, TestResultTextEncoder> textMap = new HashMap<>();
        textMap.put(TlsAnalyzedPropertyCategory.ATTACKS, getAttacksTextEncoder());
        textMap.put(TlsAnalyzedPropertyCategory.FRESHNESS, getFreshnessTextEncoder());
        textMap.put(TlsAnalyzedPropertyCategory.FFDHE, getFreshnessTextEncoder());
        TestResultTextEncoder defaultTextEncoding = getDefaultColorEncoder();

        HashMap<AnalyzedProperty, TestResultTextEncoder> specialTextMap = new HashMap<>();

        specialTextMap.put(TlsAnalyzedProperty.VULNERABLE_TO_ALPACA, getAlpacaTextEncoding());

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

    private static HashMap<TestResult, String> getDefaultTextEncodings() {
        HashMap<TestResult, String> map = new HashMap<>();
        map.put(TestResults.CANNOT_BE_TESTED, "cannot be tested");
        map.put(TestResults.COULD_NOT_TEST, "could not test");
        map.put(TestResults.ERROR_DURING_TEST, "error");
        map.put(TestResults.FALSE, "false");
        map.put(TestResults.NOT_SCHEDULED, "not tested (probe was excluded from the scan)");
        map.put(
                TestResults.NOT_TESTED_YET,
                "not tested (should've been - this is an internal error)");
        map.put(TestResults.UNASSIGNED_ERROR, "(internal error: value was never assigned)");
        map.put(TestResults.NOT_IMPLEMENTED, "not yet implemented (WIP)");
        map.put(TestResults.TIMEOUT, "timeout");
        map.put(TestResults.TRUE, "true");
        map.put(TestResults.UNCERTAIN, "uncertain");
        map.put(TestResults.PARTIALLY, "partially");
        return map;
    }

    private static TestResultTextEncoder getDefaultColorEncoder() {
        return new TestResultTextEncoder(getDefaultTextEncodings());
    }

    private static TestResultTextEncoder getFreshnessTextEncoder() {
        HashMap<TestResult, String> map = getDefaultTextEncodings();
        map.put(TestResults.COULD_NOT_TEST, "could not test (no)");
        map.put(TestResults.UNCERTAIN, "uncertain - requires manual testing");
        return new TestResultTextEncoder(map);
    }

    private static TestResultTextEncoder getAttacksTextEncoder() {
        HashMap<TestResult, String> map = getDefaultTextEncodings();
        map.put(TestResults.COULD_NOT_TEST, "could not test (not vulnerable)");
        map.put(TestResults.FALSE, "not vulnerable");
        map.put(TestResults.TRUE, "vulnerable");
        map.put(TestResults.UNCERTAIN, "uncertain - requires manual testing");
        return new TestResultTextEncoder(map);
    }

    private static TestResultTextEncoder getAlpacaTextEncoding() {
        HashMap<TestResult, String> map = getDefaultTextEncodings();
        map.put(TestResults.FALSE, "mitigated");
        map.put(TestResults.TRUE, "vulnerable");
        return new TestResultTextEncoder(map);
    }

    /**
     * Creates a color encoding with the specified colors for true and false results.
     *
     * @param trueColor The color to use when a test result is TRUE
     * @param falseColor The color to use when a test result is FALSE
     * @return A ColorEncoding with the specified color mappings
     */
    private static ColorEncoding getDefaultColorEncoding(
            SemanticMarkup trueColor, SemanticMarkup falseColor) {
        HashMap<TestResult, SemanticMarkup> colorMap = new HashMap<>();
        colorMap.put(TestResults.CANNOT_BE_TESTED, SemanticMarkup.SCANNER_INFO_SERVER_DEPENDENT);
        colorMap.put(TestResults.COULD_NOT_TEST, SemanticMarkup.SCANNER_INFO_SERVER_DEPENDENT);
        colorMap.put(TestResults.ERROR_DURING_TEST, SemanticMarkup.SCANNER_ERROR);
        colorMap.put(TestResults.UNASSIGNED_ERROR, SemanticMarkup.SCANNER_ERROR_PROGRAMMING);
        colorMap.put(TestResults.NOT_SCHEDULED, SemanticMarkup.NEUTRAL);
        colorMap.put(TestResults.NOT_TESTED_YET, SemanticMarkup.SCANNER_ERROR_PROGRAMMING);
        colorMap.put(TestResults.TIMEOUT, SemanticMarkup.SCANNER_ERROR_SERVER_DEPENDENT);
        colorMap.put(TestResults.UNCERTAIN, SemanticMarkup.RESULT_UNSURE);
        colorMap.put(TestResults.PARTIALLY, SemanticMarkup.RESULT_MEDIUM);
        colorMap.put(TestResults.FALSE, falseColor);
        colorMap.put(TestResults.TRUE, trueColor);
        return new ColorEncoding(colorMap);
    }
}
