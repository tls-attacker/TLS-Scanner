package de.rub.nds.tlsscanner.clientscanner.guideline.serialization;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.*;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.x509attacker.constants.X509Version;
import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NistGuidelineSerializationIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serialize() throws JAXBException, IOException {
        List<GuidelineCheck<ClientReport>> checks = new ArrayList<>();
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use TLS 1.2 and should be configured to use TLS 1.3.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use TLS 1.2 and should be configured to use TLS 1.3.",
                        RequirementLevel.SHOULD,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        TestResults.TRUE));
        // TODO: The client may be configured to use TLS 1.1 and TLS 1.0 to facilitate communication with private sector servers.
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall not be configured to use SSL 2.0 or SSL 3.0.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall not be configured to use SSL 2.0 or SSL 3.0.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        TestResults.FALSE));
        // TODO: Agencies shall
        //support TLS 1.3 by January 1, 2024. After this date, clients shall be configured to use TLS 1.3.
        //In general, clients that support TLS 1.3 should be configured to use TLS 1.2 as well.
        /*checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS 1.2 may be disabled on clients that support TLS 1.3 if TLS 1.2 is not needed for interoperability.",
                        RequirementLevel.MAY,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.FALSE));*/
        checks.add(
                new CertificateVersionGuidelineCheck(
                        "The TLS client certificate shall be an X.509 version 3 certificate.",
                        RequirementLevel.MUST,
                        X509Version.V3));
        checks.add(
                new KeySizeCertGuidelineCheck(
                        "Both the public key contained in the certificate and the signature shall provide at least 112 bits of security.",
                        RequirementLevel.MUST,
                        2048,
                        2048,
                        224,
                        2048));
        checks.add(
                new CertificateSignatureCheck(
                        "If the client supports TLS versions prior to TLS 1.2, the certificate should be signed with an algorithm that is consistent with the public key.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE))),
                        false));
        // TODO: extended key usage
        // TODO: Obtaining Revocation Status Information for the Server Certificate
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "Only listed Cipher Suites shall be used",
                        RequirementLevel.MUST,
                        Arrays.asList(
                                ProtocolVersion.TLS10,
                                ProtocolVersion.TLS11,
                                ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_RSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_RSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_RSA_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA)));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "Only listed Cipher Suites shall be used for TLS 1.3",
                        RequirementLevel.MUST,
                        List.of(ProtocolVersion.TLS13),
                        Arrays.asList(
                                CipherSuite.TLS_AES_128_GCM_SHA256,
                                CipherSuite.TLS_AES_256_GCM_SHA384,
                                CipherSuite.TLS_AES_128_CCM_SHA256,
                                CipherSuite.TLS_AES_128_CCM_8_SHA256)));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS implementations that support versions prior to TLS 1.3 shall use the bad_record_mac error to indicate a padding error. Implementations shall compute the MAC regardless of whether padding errors exist. TLS implementations should support constant-time decryption or near constant-time decryption.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
                        TestResults.FALSE));
        // TODO: Validated Cryptography for servers
        // TODO: The validated random number generator shall be used to generate the random bytes (32 bytes in TLS 1.3; 28 bytes in prior TLS versions) of the client random value.
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The validated random number generator should be used to generate the 4-byte timestamp of the client random value for TLS versions prior to TLS 1.3.",
                        RequirementLevel.SHOULD,
                        TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM,
                        TestResults.FALSE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the following extensions:",
                        RequirementLevel.MUST,
                        ExtensionType.RENEGOTIATION_INFO));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the following extensions:",
                        RequirementLevel.MUST,
                        ExtensionType.SERVER_NAME_INDICATION));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the following extensions:",
                        RequirementLevel.MUST,
                        ExtensionType.EXTENDED_MASTER_SECRET));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the following extensions:",
                        RequirementLevel.MUST,
                        ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS));
        // TODO: Certificate Status Request
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The Fallback Signaling Cipher Suite Value (SCSV) shall be supported if the client supports versions of TLS prior to TLS 1.2 and does not support TLS 1.3.",
                        RequirementLevel.MUST,
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
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The Supported Groups extension shall be supported if the client supports ephemeral ECDH cipher suites or if the client supports TLS 1.3.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_ECDHE,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS,  // TODO: Correct?
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Key Share extension shall be supported if the client supports TLS 1.3.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        ExtensionType.KEY_SHARE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The EC Point Format TLS extension shall be supported if the client supports EC cipher suite(s).",
                        RequirementLevel.MUST,
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
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS_1_2,
                                                                TestResults.TRUE))),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
                                                TestResults.TRUE))),
                        ExtensionType.EC_POINT_FORMATS));
        // TODO: Multiple Certificate Status
        // TODO: Trusted CA Indication
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The Encrypt-then-MAC extension shall be supported when CBC mode cipher suites are configured.",
                        RequirementLevel.MUST,
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
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS_1_2,
                                                                TestResults.TRUE))),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_CBC, // TODO: Correct?
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                        TestResults.TRUE));
        // TODO: Truncated HMAC
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Pre-Shared Key extension may be supported by TLS 1.3 clients.",
                        RequirementLevel.MAY,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        ExtensionType.PRE_SHARED_KEY));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The Pre-Shared Key Exchange Modes extension shall be supported by TLS 1.3 clients that support the Pre-Shared Key extension.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        GuidelineCheckCondition.or(
                                                Arrays.asList(
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS13_PSK,
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_TLS13_PSK_DHE,
                                                                TestResults.TRUE))),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Supported Versions extension shall be supported by TLS 1.3 clients.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        ExtensionType.SUPPORTED_VERSIONS));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Cookie extension shall be supported by TLS 1.3 clients.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        ExtensionType.COOKIE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Certificate Signature Algorithms Extension shall be supported if the client supports TLS 1.3 and should be supported for TLS 1.2.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        ExtensionType.SIGNATURE_ALGORITHMS_CERT));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Certificate Signature Algorithms Extension shall be supported if the client supports TLS 1.3 and should be supported for TLS 1.2.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                TestResults.TRUE),
                        ExtensionType.SIGNATURE_ALGORITHMS_CERT));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Post-handshake Client Authentication extension may be supported if the client supports TLS 1.3.",
                        RequirementLevel.MAY,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        ExtensionType.POST_HANDSHAKE_AUTH));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The following extensions should not be used:",
                        RequirementLevel.SHOULD_NOT,
                        ExtensionType.CLIENT_CERTIFICATE_URL));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The following extensions should not be used:",
                        RequirementLevel.SHOULD_NOT,
                        ExtensionType.EARLY_DATA));
        // TODO: Server Authentication and Path Validation
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Therefore, clients using TLS 1.3 should not send 0-RTT data.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT,
                        TestResults.FALSE
                ));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS 1.2 clients shall not use False Start.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The null compression method shall be enabled, and all other compression methods shall be disabled.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                        TestResults.FALSE));

        Guideline<ClientReport> guideline =
                new Guideline<>(
                        "NIST SP 800-52r2", "https://doi.org/10.6028/NIST.SP.800-52r2", checks);
        GuidelineIO guidelineIO = new GuidelineIO(TlsAnalyzedProperty.class);
        guidelineIO.write(Paths.get("src/main/resources/guideline/nist.xml").toFile(), guideline);
    }
}
