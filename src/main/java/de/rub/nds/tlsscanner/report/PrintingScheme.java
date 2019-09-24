/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.constants.AnsiColor;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.AnalyzedPropertyCategory;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PrintingScheme {

    private static final Logger LOGGER = LogManager.getLogger();

    private HashMap<AnalyzedProperty, ColorEncoding> colorEncodings;

    private HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings;

    private TextEncoding defaultTextEncoding;
    private ColorEncoding defaultColorEncoding;

    public PrintingScheme() {
    }

    public PrintingScheme(HashMap<AnalyzedProperty, ColorEncoding> colorEncodings, HashMap<AnalyzedPropertyCategory, TextEncoding> textEncodings, TextEncoding defaultTextEncoding, ColorEncoding defaultColorEncoding) {
        this.colorEncodings = colorEncodings;
        this.textEncodings = textEncodings;
        this.defaultTextEncoding = defaultTextEncoding;
        this.defaultColorEncoding = defaultColorEncoding;
    }

    public HashMap<AnalyzedProperty, ColorEncoding> getColorEncodings() {
        return colorEncodings;
    }

    public HashMap<AnalyzedPropertyCategory, TextEncoding> getTextEncodings() {
        return textEncodings;
    }

    public String getEncodedString(SiteReport report, AnalyzedProperty property) {
        TestResult result = report.getResult(property);
        TextEncoding textEncoding = textEncodings.getOrDefault(property.getCategory(), defaultTextEncoding);
        ColorEncoding colorEncoding = colorEncodings.getOrDefault(result, defaultColorEncoding);
        String encodedText = textEncoding.encode(result);
        return colorEncoding.encode(result, encodedText);
    }

    public static PrintingScheme getDefaultPrintingScheme() {
        HashMap<TestResult, String> textEncodingMap = new HashMap<>();
        textEncodingMap.put(TestResult.COULD_NOT_TEST, "could not test");
        textEncodingMap.put(TestResult.ERROR_DURING_TEST, "error");
        textEncodingMap.put(TestResult.FALSE, "false");
        textEncodingMap.put(TestResult.NOT_TESTED_YET, "not tested yet");
        textEncodingMap.put(TestResult.TIMEOUT, "timeout");
        textEncodingMap.put(TestResult.TRUE, "true");
        textEncodingMap.put(TestResult.UNCERTAIN, "uncertain");
        textEncodingMap.put(TestResult.UNSUPPORTED, "unsupported by tls-scanner");
        TextEncoding defaultTextEncoding = new TextEncoding(textEncodingMap);
        HashMap<TestResult, AnsiColor> ansiColorMap = new HashMap<>();
        ansiColorMap.put(TestResult.COULD_NOT_TEST, AnsiColor.BLUE);
        ansiColorMap.put(TestResult.ERROR_DURING_TEST, AnsiColor.RED_BACKGROUND);
        ansiColorMap.put(TestResult.FALSE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResult.NOT_TESTED_YET, AnsiColor.WHITE);
        ansiColorMap.put(TestResult.TIMEOUT, AnsiColor.PURPLE_BACKGROUND);
        ansiColorMap.put(TestResult.TRUE, AnsiColor.DEFAULT_COLOR);
        ansiColorMap.put(TestResult.UNCERTAIN, AnsiColor.YELLOW_BACKGROUND);
        ansiColorMap.put(TestResult.UNSUPPORTED, AnsiColor.CYAN);
        ColorEncoding defaultColorEncoding = new ColorEncoding(ansiColorMap);

        HashMap<TestResult, String> attackEncodingMap = new HashMap<>();
        attackEncodingMap.put(TestResult.COULD_NOT_TEST, "could not test (not vulnerable)");
        attackEncodingMap.put(TestResult.ERROR_DURING_TEST, "error");
        attackEncodingMap.put(TestResult.FALSE, "not vulnerable");
        attackEncodingMap.put(TestResult.NOT_TESTED_YET, "not tested yet");
        attackEncodingMap.put(TestResult.TIMEOUT, "timeout");
        attackEncodingMap.put(TestResult.TRUE, "vulnerable");
        attackEncodingMap.put(TestResult.UNCERTAIN, "uncertain - requires manual testing");
        attackEncodingMap.put(TestResult.UNSUPPORTED, "unsupported by TLS-Scanner");

        ColorEncoding attacks = getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN);

        HashMap<AnalyzedProperty, ColorEncoding> colorMap = new HashMap<>();
        for (AnalyzedProperty prop : AnalyzedProperty.values()) {
            if (prop.getCategory() == AnalyzedPropertyCategory.ATTACKS) {
                colorMap.put(prop, attacks);
            }
        }
        colorMap.put(AnalyzedProperty.SUPPORTS_SSL_2,getDefaultColorEncoding(AnsiColor.RED, AnsiColor.GREEN));
        colorMap.put(AnalyzedProperty.SUPPORTS_SSL_3);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_0);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_1);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_2);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28);
        colorMap.put(AnalyzedProperty.SUPPORTS_DTLS_1_0);
        colorMap.put(AnalyzedProperty.SUPPORTS_DTLS_1_2);
        colorMap.put(AnalyzedProperty.SUPPORTS_DTLS_1_3);
        colorMap.put(AnalyzedProperty.SUPPORTS_PFS);
        colorMap.put(AnalyzedProperty.SUPPORTS_NULL_CIPHERS);
        colorMap.put(AnalyzedProperty.SUPPORTS_FORTEZZA);
        colorMap.put(AnalyzedProperty.SUPPORTS_EXPORT);
        colorMap.put(AnalyzedProperty.SUPPORTS_ANON);
        colorMap.put(AnalyzedProperty.SUPPORTS_DES);
        colorMap.put(AnalyzedProperty.SUPPORTS_3DES);
        colorMap.put(AnalyzedProperty.SUPPORTS_SEED);
        colorMap.put(AnalyzedProperty.SUPPORTS_IDEA);
        colorMap.put(AnalyzedProperty.SUPPORTS_RC2);
        colorMap.put(AnalyzedProperty.SUPPORTS_RC4);
        colorMap.put(AnalyzedProperty.SUPPORTS_CBC);
        colorMap.put(AnalyzedProperty.SUPPORTS_AEAD);
        colorMap.put(AnalyzedProperty.SUPPORTS_POST_QUANTUM);
        colorMap.put(AnalyzedProperty.SUPPORTS_ONLY_PFS);
        colorMap.put(AnalyzedProperty.SUPPORTS_AES);
        colorMap.put(AnalyzedProperty.SUPPORTS_CAMELLIA);
        colorMap.put(AnalyzedProperty.SUPPORTS_ARIA);
        colorMap.put(AnalyzedProperty.SUPPORTS_CHACHA);
        colorMap.put(AnalyzedProperty.SUPPORTS_RSA);
        colorMap.put(AnalyzedProperty.SUPPORTS_DH);
        colorMap.put(AnalyzedProperty.SUPPORTS_ECDH);
        colorMap.put(AnalyzedProperty.SUPPORTS_STATIC_ECDH);
        colorMap.put(AnalyzedProperty.SUPPORTS_GOST);
        colorMap.put(AnalyzedProperty.SUPPORTS_SRP);
        colorMap.put(AnalyzedProperty.SUPPORTS_KERBEROS);
        colorMap.put(AnalyzedProperty.SUPPORTS_PSK_PLAIN);
        colorMap.put(AnalyzedProperty.SUPPORTS_PSK_RSA);
        colorMap.put(AnalyzedProperty.SUPPORTS_PSK_DHE);
        colorMap.put(AnalyyzedProperty.SUPPORTS_PSK_ECDHE);
        colorMap.put(AnalyzedProperty.SUPPORTS_NEWHOPE);
        colorMap.put(AnalyzedProperty.SUPPORTS_ECMQV);
        colorMap.put(AnalyzedProperty.SUPPORTS_STREAM_CIPHERS);
        colorMap.put(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);
        colorMap.put(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET);
        colorMap.put(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC);
        colorMap.put(AnalyzedProperty.SUPPORTS_TOKENBINDING);
        colorMap.put(AnalyzedProperty.SUPPORTS_MONTOGMERY_CURVES);
        colorMap.put(AnalyzedProperty.SUPPORTS_SESSION_TICKETS);
        colorMap.put(AnalyzedProperty.SUPPORTS_SESSION_IDS);
        colorMap.put(AnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT);
        colorMap.put(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
        colorMap.put(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION);
        colorMap.put(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV);
        colorMap.put(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION SUPPORTS_COMMON_DH_PRIMES);
        colorMap.put(AnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI);
        colorMap.put(AnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI);
        colorMap.put(AnalyzedProperty.SUPPORTS_INSECURE_RENEGOTIATION);
        colorMap.put(AnalyzedProperty.SUPPORTS_RENEGOTIATION SUPPORTS_HTTPS);
        colorMap.put(AnalyzedProperty.SUPPORTS_HSTS);
        colorMap.put(AnalyzedProperty.SUPPORTS_HSTS_PRELOADING);
        colorMap.put(AnalyzedProperty.SUPPORTS_HPKP);
        colorMap.put(AnalyzedProperty.SUPPORTS_HPKP_REPORTING);
        colorMap.put(AnalyzedProperty.SUPPORTS_HTTP_COMPRESSION);
        colorMap.put(AnalyzedProperty.PREFERS_PFS);
        colorMap.put(AnalyzedProperty.ENFORCES_PFS);
        colorMap.put(AnalyzedProperty.ENFOCRES_CS_ORDERING);
        colorMap.put(AnalyzedProperty.HAS_VERSION_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_CIPHERSUITE_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_CIPHERSUITE_LENGTH_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_ALPN_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE);
        colorMap.put(AnalyzedProperty.HAS_SECOND_CIPHERSUITE_BYTE_BUG);
        colorMap.put(AnalyzedProperty.REFLECTS_OFFERED_CIPHERSUITES);
        colorMap.put(AnalyzedProperty.IGNORES_OFFERED_CIPHERSUITES);
        colorMap.put(AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS);
        colorMap.put(AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_POODLE);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_SWEET_32);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_DROWN);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_TICKETBLEED);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_CRIME);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_BREACH);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_LOGJAM);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_FREAK);
        colorMap.put(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK);
        colorMap.put(AnalyzedProperty.MISSES_MAC_APPDATA_CHECKS);
        colorMap.put(AnalyzedProperty.MISSES_MAC_FINISHED_CHECKS);
        colorMap.put(AnalyzedProperty.MISSES_VERIFY_DATA_CHECKS);
        colorMap.put(AnalyzedProperty.MISSES_GCM_CHECKS);
        colorMap.put(AnalyzedProperty.HAS_CERTIFICATE_ISSUES);
        colorMap.put(AnalyzedProperty.HAS_WEAK_RANDOMNESS);
        colorMap.put(AnalyzedProperty.REUSES_EC_PUBLICKEY);
        colorMap.put(AnalyzedProperty.REUSES_DH_PUBLICKEY);
        colorMap.put(AnalyzedProperty.REUSES_GCM_NONCES);
        colorMap.put(AnalyzedProperty.REQUIRES_SNI,);

        HashMap<AnalyzedPropertyCategory, TextEncoding> textMap = new HashMap<>();
        textMap.put(AnalyzedPropertyCategory.ATTACKS, new TextEncoding(attackEncodingMap));
        PrintingScheme scheme = new PrintingScheme(colorMap, textMap, defaultTextEncoding, defaultColorEncoding);
        return scheme;
    }

    private static ColorEncoding getDefaultColorEncoding(AnsiColor trueColor, AnsiColor falseColor) {
        HashMap<TestResult, AnsiColor> colorMap = new HashMap<>();
        colorMap.put(TestResult.COULD_NOT_TEST, AnsiColor.BLUE);
        colorMap.put(TestResult.ERROR_DURING_TEST, AnsiColor.RED_BACKGROUND);
        colorMap.put(TestResult.FALSE, falseColor);
        colorMap.put(TestResult.NOT_TESTED_YET, AnsiColor.WHITE);
        colorMap.put(TestResult.TIMEOUT, AnsiColor.PURPLE_BACKGROUND);
        colorMap.put(TestResult.TRUE, trueColor);
        colorMap.put(TestResult.UNCERTAIN, AnsiColor.YELLOW_BACKGROUND);
        colorMap.put(TestResult.UNSUPPORTED, AnsiColor.CYAN);
        return new ColorEncoding(colorMap);
    }
}
