/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.serialization;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.guideline.Guideline;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineIO;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateSignatureCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateValidityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateVersionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtendedKeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmStrengthCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NistGuidelineSerialization {

    @Test
    public void serialize() throws JAXBException {
        List<GuidelineCheck> checks = new ArrayList<>();
        checks.add(new AnalyzedPropertyGuidelineCheck("Servers shall support TLS 1.2.", RequirementLevel.MUST,
            AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Servers should support TLS 1.3 and shall support TLS 1.3 by January 1, 2024.", RequirementLevel.SHOULD,
            AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Support of TLS 1.0 is discouraged.", RequirementLevel.MAY,
            AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Support of TLS 1.1 is discouraged.", RequirementLevel.MAY,
            AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Servers shall not support SSL 3.0.", RequirementLevel.MUST,
            AnalyzedProperty.SUPPORTS_SSL_3, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Servers shall not support SSL 2.0.", RequirementLevel.MUST,
            AnalyzedProperty.SUPPORTS_SSL_2, TestResult.FALSE));
        checks.add(new CertificateAgilityGuidelineCheck(
            "Should support the use of multiple server certificates with their associated private keys to support algorithm and key size agility",
            RequirementLevel.SHOULD));
        checks.add(new SignatureAlgorithmsCertificateGuidelineCheck(
            "Shall be configured with an RSA signature certificate or an ECDSA signature certificate",
            RequirementLevel.MUST, true, Arrays.asList(SignatureAlgorithm.RSA, SignatureAlgorithm.ECDSA)));
        checks.add(
            new CertificateCurveGuidelineCheck("For ECDSA: Curve P-256 or curve P-384 should be used in the public key",
                RequirementLevel.SHOULD, Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1)));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Certificates shall be issued by CA that publishes revocation information in OCSP responses",
            RequirementLevel.MUST, AnalyzedProperty.SUPPORTS_OCSP, TestResult.TRUE));
        checks.add(new CertificateVersionGuidelineCheck("Server certificate shall be an X.509 version 3 certificate",
            RequirementLevel.MUST, 3));
        checks.add(new KeySizeCertGuidelineCheck(
            "All server and client certificates shall contain public keys that offer at least 112 bits of security.",
            RequirementLevel.MUST, 2048, 2048, 224, 2048));
        checks.add(new CertificateSignatureCheck(
            "If the server supports TLS versions prior to TLS 1.2, the certificate should be signed with an algorithm consistent with the public key",
            RequirementLevel.SHOULD,
            GuidelineCheckCondition
                .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE))),
            false));
        checks.add(new CertificateValidityGuidelineCheck("Certificate Validity Period should be 3 years or less.",
            RequirementLevel.SHOULD, 1095));
        checks.add(new KeyUsageCertificateCheck(
            "Key Usage Extension should be used with digitalSignature and keyAgreement values.",
            RequirementLevel.SHOULD));
        checks.add(new ExtendedKeyUsageCertificateCheck(
            "Server should be configured to allow use of extended key usage extension with key purpose specifically for server authentication",
            RequirementLevel.SHOULD));
        checks.add(new CipherSuiteGuidelineCheck("Only listed Cipher Suites shall be used", RequirementLevel.MUST,
            Arrays.asList(ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12),
            Arrays.asList(CipherSuite.TLS_RSA_WITH_AES_128_CCM, CipherSuite.TLS_RSA_WITH_AES_256_CCM,
                CipherSuite.TLS_RSA_WITH_AES_128_CCM_8, CipherSuite.TLS_RSA_WITH_AES_256_CCM_8,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,

                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,

                CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,

                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,

                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,

                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA,

                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,

                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,

                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,

                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,

                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,

                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA)));
        checks.add(new CipherSuiteGuidelineCheck("Only listed Cipher Suites shall be used for TLS 1.3",
            RequirementLevel.MUST, Arrays.asList(ProtocolVersion.TLS13),
            Arrays.asList(CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_AES_128_CCM_SHA256, CipherSuite.TLS_AES_128_CCM_8_SHA256)));
        checks.add(new AnalyzedPropertyGuidelineCheck("Servers shall not be vulnerable to padding oracle.",
            RequirementLevel.MUST, AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck("Servers shall not be vulnerable to POODLE attack.",
            RequirementLevel.MUST, AnalyzedProperty.VULNERABLE_TO_TLS_POODLE, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The random number generator should be used to generate the 4-byte timestamp of the server random value.",
            RequirementLevel.SHOULD, AnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM, TestResult.FALSE));
        checks.add(new HashAlgorithmStrengthCheck(
            "All server and client certificates and certificates in their certification paths shall be signed using SHA-224 or a stronger hashing algorithm.",
            RequirementLevel.MUST, HashAlgorithm.SHA224));
        checks.add(new AnalyzedPropertyGuidelineCheck("The server shall support secure renegotiation Extension.",
            RequirementLevel.MUST,
            GuidelineCheckCondition
                .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE))),
            AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, TestResult.TRUE));
        checks.add(new ExtensionGuidelineCheck(
            "The server shall be able to process and respond to the server name indication extension.",
            RequirementLevel.MUST, ExtensionType.SERVER_NAME_INDICATION));
        checks.add(new AnalyzedPropertyGuidelineCheck("The Extended Master Secret extension shall be supported.",
            RequirementLevel.MUST,
            GuidelineCheckCondition
                .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE))),
            AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Servers shall support the processing of the signature algorithms extension received in a ClientHello message.",
            RequirementLevel.MUST,
            GuidelineCheckCondition
                .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE))),
            AnalyzedProperty.RESPECTS_SIGNATURE_ALGORITHMS_EXTENSION, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck("The Certificate Status Request extension shall be supported.",
            RequirementLevel.MUST, AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The Fallback Signaling Cipher Suite Value (SCSV) shall be supported if the server supports versions of TLS prior to TLS 1.2 and does not support TLS 1.3.",
            RequirementLevel.MUST,
            GuidelineCheckCondition.and(Arrays.asList(
                GuidelineCheckCondition
                    .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE))),
                new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.FALSE))),
            AnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, TestResult.TRUE));
        checks.add(new NamedGroupsGuidelineCheck(
            "When elliptic curve cipher suites are configured, at least one of the NIST-approved curves, P-256 (secp256r1) and P-384 (secp384r1), shall be supported as described in RFC 8422. Additional NIST-recommended elliptic curves are listed in SP 800-56A, Appendix D. Finite field groups that are approved for TLS in SP 800-56A, Appendix D may be supported.",
            RequirementLevel.MUST,
            GuidelineCheckCondition
                .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_ECDHE, TestResult.TRUE),
                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE))),
            Arrays.asList(NamedGroup.SECP224R1, NamedGroup.SECP256R1, NamedGroup.SECP384R1, NamedGroup.SECP521R1,
                NamedGroup.SECT233K1, NamedGroup.SECT283K1, NamedGroup.SECT409K1, NamedGroup.SECT571K1,
                NamedGroup.SECT233R1, NamedGroup.SECT283R1, NamedGroup.SECT409R1, NamedGroup.SECT571R1,
                NamedGroup.FFDHE2048, NamedGroup.FFDHE3072, NamedGroup.FFDHE4096, NamedGroup.FFDHE6144,
                NamedGroup.FFDHE8192

            ), Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1), false, 2));
        checks.add(new ExtensionGuidelineCheck(
            "The Key Share extension shall be supported if the server supports TLS 1.3", RequirementLevel.MUST,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE), ExtensionType.KEY_SHARE));
        checks
            .add(
                new ExtensionGuidelineCheck(
                    "The EC Point Format extension shall be supported if the server supports EC cipher suites",
                    RequirementLevel.MUST,
                    GuidelineCheckCondition
                        .and(
                            Arrays
                                .asList(
                                    GuidelineCheckCondition.or(Arrays.asList(
                                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE),
                                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2,
                                            TestResult.TRUE))),
                                    new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_ECDH, TestResult.TRUE))),
                    ExtensionType.EC_POINT_FORMATS));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The Multiple Certificate Status extension should be supported if status information for the server’s certificate is available via OCSP and the extension is supported by the server implementation",
            RequirementLevel.SHOULD,
            GuidelineCheckCondition.and(Arrays.asList(
                GuidelineCheckCondition
                    .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE))),
                new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_OCSP, TestResult.TRUE))),
            AnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The Encrypt-then-MAC extension shall be supported if the server is configured to negotiate CBC cipher suites.",
            RequirementLevel.MUST,
            GuidelineCheckCondition.and(Arrays.asList(
                GuidelineCheckCondition
                    .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_0, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_1, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_2, TestResult.TRUE))),
                new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, TestResult.TRUE))),
            AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, TestResult.TRUE));

        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The Pre-Shared Key Exchange Modes extension shall be supported if the server supports TLS 1.3 and the Pre-Shared Key extension.",
            RequirementLevel.MUST,
            GuidelineCheckCondition.and(Arrays.asList(
                GuidelineCheckCondition
                    .or(Arrays.asList(new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS13_PSK, TestResult.TRUE),
                        new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, TestResult.TRUE))),
                new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE))),
            AnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES, TestResult.TRUE));
        checks.add(new ExtensionGuidelineCheck(
            "The Supported Versions extension shall be supported if the server supports TLS 1.3", RequirementLevel.MUST,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            ExtensionType.SUPPORTED_VERSIONS));
        checks.add(new ExtensionGuidelineCheck("Servers that support TLS 1.3 may support the cookie extension",
            RequirementLevel.MAY, new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            ExtensionType.COOKIE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The Signed Certificate Timestamps extension should be supported if the server’s certificate was issued by a publicly trusted CA and the certificate does not include a Signed Certificate Timestamps List extension.",
            RequirementLevel.SHOULD,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE, TestResult.FALSE),
            AnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "Servers should not process early data received in the ClientHello message.", RequirementLevel.SHOULD,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS_1_3, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_TLS13_0_RTT, TestResult.FALSE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "If the server does allow 0-RTT data, then the server should use the single-use ticket mechanism.",
            RequirementLevel.SHOULD,
            new GuidelineCheckCondition(AnalyzedProperty.SUPPORTS_TLS13_0_RTT, TestResult.TRUE),
            AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, TestResult.TRUE));
        checks.add(new AnalyzedPropertyGuidelineCheck(
            "The null compression method shall be enabled, and all other compression methods shall be disabled.",
            RequirementLevel.MUST, AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, TestResult.FALSE));

        Guideline guideline = new Guideline("NIST SP 800-52r2", "https://doi.org/10.6028/NIST.SP.800-52r2", checks);
        GuidelineIO.writeGuideline(guideline, Paths.get("src/main/resources/guideline/nist.xml"));
    }
}
