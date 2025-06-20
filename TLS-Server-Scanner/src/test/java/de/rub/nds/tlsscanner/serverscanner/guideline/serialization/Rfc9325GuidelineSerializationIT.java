/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.Guideline;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineIO;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NotRecommendedCipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NotRecommendedExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NotRecommendedHashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.RecommendedCipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.RecommendedExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.RecommendedHashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class Rfc9325GuidelineSerializationIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serialize() throws JAXBException, IOException {
        List<GuidelineCheck<ServerReport>> checks = new ArrayList<>();

        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations MUST NOT negotiate SSL version 2.",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations MUST NOT negotiate SSL version 3.",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations MUST NOT negotiate TLS version 1.0 [RFC2246].",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations MUST NOT negotiate TLS version 1.1 [RFC4346].",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations MUST support TLS 1.2 [RFC5246].",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Implementations SHOULD support TLS 1.3 [RFC8446].",
                        RequirementLevel.SHOULD,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS/DTLS 1.2 clients MUST NOT fall back to earlier TLS versions, since those versions have been deprecated [RFC8996]. As a result, the downgrade-protection Signaling Cipher Suite Value (SCSV) mechanism [RFC7507] is no longer needed for clients.",
                        RequirementLevel.MUST_NOT,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        GuidelineCheckCondition.or(
                                                Arrays.asList(
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS_1_0,
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS_1_1,
                                                                TestResults.TRUE))),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.FALSE))),
                        TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "In order to help prevent compression-related attacks (summarized in Section 2.6 of [RFC7457]) when using TLS 1.2, implementations and deployments SHOULD NOT support TLS-level compression (Section 6.2.2 of [RFC5246]).",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "In order to gain forward secrecy, this document recommends that server implementations SHOULD **select the \"psk_dhe_ke\" PSK key exchange mode** and respond with a \"key_share\" to complete an Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) exchange on each session resumption.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SELECTS_TLS13_PSK_DHE,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "In order to gain forward secrecy, this document recommends that server implementations SHOULD select the \"psk_dhe_ke\" PSK key exchange mode and **respond with a \"key_share\"** to complete an Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) exchange on each session resumption.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES,
                        TestResults.TRUE));
        checks.add(
                new RecommendedExtensionGuidelineCheck(
                        "TLS 1.2 clients and servers MUST implement the renegotiation_info extension, as defined in [RFC5746].",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        ExtensionType.RENEGOTIATION_INFO));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS 1.2 implementations MUST support the extended_master_secret extension defined in [RFC7627].",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                        TestResults.TRUE));
        checks.add(
                new RecommendedExtensionGuidelineCheck(
                        "TLS implementations MUST support the Server Name Indication (SNI) extension defined in Section 3 of [RFC6066].",
                        RequirementLevel.MUST,
                        ExtensionType.SERVER_NAME_INDICATION));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "In order to prevent the attacks described in [ALPACA], a server that does not recognize the presented server name SHOULD NOT continue the handshake.",
                        RequirementLevel.SHOULD_NOT,
                        TlsAnalyzedProperty.STRICT_SNI,
                        TestResults.TRUE));
        checks.add(
                new RecommendedExtensionGuidelineCheck(
                        "TLS implementations (both client- and server-side) MUST support the Application-Layer Protocol Negotiation (ALPN) extension [RFC7301].",
                        RequirementLevel.MUST,
                        ExtensionType.ALPN));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "In the event that the server supports no protocols that the client advertises, then the server SHALL respond with a fatal 'no_application_protocol' alert.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.STRICT_ALPN,
                        TestResults.TRUE));
        // Cipher Suites (RFC uses a "MUST NOT/SHOULD NOT"-approach instead of an allowlist)
        checks.add(
                new NotRecommendedCipherSuiteGuidelineCheck(
                        "Implementations MUST NOT negotiate the cipher suites with NULL encryption. Implementations MUST NOT negotiate RC4 cipher suites. Implementations MUST NOT negotiate cipher suites offering less than 112 bits of security, including so-called \"export-level\" encryption (which provides 40 or 56 bits of security).",
                        RequirementLevel.MUST_NOT,
                        List.of(ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384,
                                CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
                                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA,
                                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256,
                                CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384,
                                CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA,
                                CipherSuite.TLS_NULL_WITH_NULL_NULL,
                                CipherSuite.TLS_PSK_WITH_NULL_SHA,
                                CipherSuite.TLS_PSK_WITH_NULL_SHA256,
                                CipherSuite.TLS_PSK_WITH_NULL_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA,
                                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384,
                                CipherSuite.TLS_RSA_WITH_NULL_MD5,
                                CipherSuite.TLS_RSA_WITH_NULL_SHA,
                                CipherSuite.TLS_RSA_WITH_NULL_SHA256,
                                CipherSuite.TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                                CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5,
                                CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
                                CipherSuite.TLS_KRB5_WITH_RC4_128_MD5,
                                CipherSuite.TLS_KRB5_WITH_RC4_128_SHA,
                                CipherSuite.TLS_PSK_WITH_RC4_128_SHA,
                                CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
                                CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA,
                                CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
                                CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                                CipherSuite.TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
                                CipherSuite.TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
                                CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5)));
        checks.add(
                new NotRecommendedCipherSuiteGuidelineCheck(
                        "Implementations SHOULD NOT negotiate cipher suites that use algorithms offering less than 128 bits of security. Implementations SHOULD NOT negotiate cipher suites based on RSA key transport, a.k.a. \"static RSA\". Implementations SHOULD NOT negotiate cipher suites based on non-ephemeral (static) finite-field Diffie-Hellman (DH) key agreement. Similarly, implementations SHOULD NOT negotiate non-ephemeral Elliptic Curve DH key agreement. TLS 1.2 implementations SHOULD NOT negotiate cipher suites based on ephemeral finite-field Diffie-Hellman key agreement (i.e., \"TLS_DHE_*\" suites).",
                        RequirementLevel.SHOULD_NOT,
                        List.of(ProtocolVersion.TLS12),
                        Arrays.asList( // All cipher suites that MUST NOT be used removed from
                                // this list.
                                CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
                                CipherSuite.TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_RSA_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_anon_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA,
                                CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA)));
        checks.add(
                new RecommendedCipherSuiteGuidelineCheck(
                        "Given the foregoing considerations, implementation and deployment of the following cipher suites is RECOMMENDED.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        List.of(ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)));
        checks.add(
                new NotRecommendedCipherSuiteGuidelineCheck(
                        "A cipher suite that operates in CBC (cipher block chaining) mode (e.g., TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) SHOULD NOT be used unless the encrypt_then_mac extension [RFC7366] is also successfully negotiated. This requirement applies to both client and server implementations.",
                        RequirementLevel.SHOULD_NOT,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                                                TestResults.FALSE))),
                        List.of(ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)));
        checks.add(
                new CertificateCurveGuidelineCheck(
                        "When using ECDSA signatures for authentication of TLS peers, it is RECOMMENDED that implementations use the NIST curve P-256.",
                        RequirementLevel.SHOULD,
                        List.of(X509NamedCurve.SECP256R1)));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Clients SHOULD include TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as the first proposal to any server. Servers MUST prefer this cipher suite over weaker cipher suites whenever it is proposed, even if it is not the first proposal.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.AVOIDS_WEAKER_CIPHER_SUITES_RFC9325,
                        TestResults.TRUE));
        checks.add(
                new NotRecommendedCipherSuiteGuidelineCheck(
                        "The previous version of the TLS recommendations [RFC7525] implicitly allowed [...] TLS_RSA_WITH_AES_128_CBC_SHA. [...] As with other cipher suites that do not provide forward secrecy, implementations SHOULD NOT support this cipher suite.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        List.of(ProtocolVersion.TLS12),
                        List.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)));
        checks.add(
                new RecommendedExtensionGuidelineCheck(
                        "Both clients and servers SHOULD include the \"Supported Elliptic Curves Extension\" [RFC8422].",
                        RequirementLevel.SHOULD,
                        ExtensionType.ELLIPTIC_CURVES));
        checks.add(
                new NamedGroupsGuidelineCheck(
                        "Clients and servers SHOULD support the NIST P‑256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves.",
                        RequirementLevel.SHOULD,
                        Arrays.asList(NamedGroup.SECP256R1, NamedGroup.ECDH_X25519),
                        Collections.emptyList(),
                        false,
                        2));
        checks.add(
                new NamedGroupsGuidelineCheck(
                        "Clients and servers SHOULD support the NIST P‑256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves.",
                        RequirementLevel.SHOULD,
                        Arrays.asList(NamedGroup.SECP256R1, NamedGroup.ECDH_X25519),
                        Collections.emptyList(),
                        true,
                        2));
        checks.add(
                new KeySizeCertGuidelineCheck( // DSA not allowed, thus minimumDsaKeyLength set to 0
                        "4.5. Public Key Length", RequirementLevel.MUST, 0, 2048, 224, 2048));
        checks.add(
                new RecommendedHashAlgorithmsGuidelineCheck(
                        "In addition, the use of the SHA-256 hash algorithm is RECOMMENDED and SHA-1 or MD5 MUST NOT be used [RFC9155] (for more details, see also [CAB-Baseline], for which the current version at the time of writing is 1.8.4).",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        List.of(HashAlgorithm.SHA256)));
        checks.add(
                new NotRecommendedHashAlgorithmsGuidelineCheck(
                        "In addition, the use of the SHA-256 hash algorithm is RECOMMENDED and SHA-1 or MD5 MUST NOT be used [RFC9155] (for more details, see also [CAB-Baseline], for which the current version at the time of writing is 1.8.4).",
                        RequirementLevel.MUST_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        Arrays.asList(HashAlgorithm.SHA1, HashAlgorithm.MD5)));
        checks.add(
                new NotRecommendedExtensionGuidelineCheck(
                        "Implementations MUST NOT use the Truncated HMAC Extension, defined in Section 7 of [RFC6066].",
                        RequirementLevel.MUST_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        ExtensionType.TRUNCATED_HMAC));

        // TODO for the future: Evaluate whether this can be tested, is worth the effort, and if so
        // implement it here. "It is therefore RECOMMENDED that TLS 1.2 implementations use the
        // 64-bit sequence number to populate the nonce_explicit part of the GCM nonce, as described
        // in the first two paragraphs of Section 5.3 of [RFC8446]." (7.2.1. Nonce Reuse in TLS 1.2)

        // TODO: Implement serverscanner probe that sets TlsAnalyzedProperty.SUPPORTS_OCSP (see
        // issue #199).
        //        checks.add(
        //                new AnalyzedPropertyGuidelineCheck(
        //                        "For the common use cases of public key certificates in TLS,
        // servers SHOULD support the following as a best practice given the current state of the
        // art and as a foundation for a possible future solution: OCSP [RFC6960] and OCSP stapling
        // using the status_request extension defined in [RFC6066].",
        //                        RequirementLevel.SHOULD,
        //                        TlsAnalyzedProperty.SUPPORTS_OCSP,
        //                        TestResults.TRUE));

        Guideline<ServerReport> guideline =
                new Guideline<>(
                        "IETF RFC 9325: Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)",
                        "https://datatracker.ietf.org/doc/rfc9325/",
                        checks);
        GuidelineIO guidelineIO = new GuidelineIO(TlsAnalyzedProperty.class);
        guidelineIO.write(
                Paths.get("src/main/resources/guideline/rfc9325.xml").toFile(), guideline);
    }
}
