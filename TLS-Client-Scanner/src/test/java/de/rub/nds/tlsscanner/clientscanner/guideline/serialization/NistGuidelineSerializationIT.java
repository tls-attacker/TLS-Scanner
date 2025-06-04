/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.serialization;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.*;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509Version;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class NistGuidelineSerializationIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serialize() throws JAXBException, IOException {
        List<GuidelineCheck<ClientReport>> checks = new ArrayList<>();
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "After this date [January 1, 2024], clients shall be configured to use TLS 1.3.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use TLS 1.2.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client may be configured to use TLS 1.1 and TLS 1.0 to facilitate communication with private sector servers.",
                        RequirementLevel.MAY,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client may be configured to use TLS 1.1 and TLS 1.0 to facilitate communication with private sector servers.",
                        RequirementLevel.MAY,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall not be configured to use SSL 2.0 or SSL 3.0.",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall not be configured to use SSL 2.0 or SSL 3.0.",
                        RequirementLevel.MUST_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        TestResults.FALSE));
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
        checks.add(
                new CertificateNameGuidelineCheck(
                        "Issuer Distinguished Name (DN): A single value should be encoded in each RDN. All attributes that are of directoryString type should be encoded as a printable string. [...] Subject Distinguished Name: A single value should be encoded in each RDN. All attributes that are of directoryString type should be encoded as a printable string.",
                        RequirementLevel.SHOULD,
                        false));
        checks.add(
                new CertificateCurveGuidelineCheck(
                        "ECDSA signature certificate or ECDH certificate: The curve should be P-256 or P-384.",
                        RequirementLevel.SHOULD,
                        Arrays.asList(X509NamedCurve.SECP256R1, X509NamedCurve.SECP384R1)));

        // TODO: If the EKU extension is included in client certificates, then the id-kp-client-auth
        // key purpose OID should be included in the certificates to be used for TLS client
        // authentication and should be omitted from any other certificates.

        // TODO: Implement clientscanner probe that sets TlsAnalyzedProperty.SUPPORTS_OCSP.
        //        checks.add(
        //                new AnalyzedPropertyGuidelineCheck(
        //                        "The client shall perform revocation checking of the server
        // certificate.",
        //                        RequirementLevel.MUST,
        //                        TlsAnalyzedProperty.SUPPORTS_OCSP,
        //                        TestResults.TRUE));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "The client should not be configured to use cipher suites other than those listed in Section 3.3.1, Appendix C, or Appendix D. [...] The cipher suite requirement for clients is weaker than for servers because many clients, such as web browsers, may not allow the same level of configuration as servers. [...] Section 3.3.1:",
                        RequirementLevel.SHOULD,
                        Arrays.asList(
                                ProtocolVersion.TLS10,
                                ProtocolVersion.TLS11,
                                ProtocolVersion.TLS12),
                        Arrays.asList(
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
                        "The client should not be configured to use cipher suites other than those listed in Section 3.3.1, Appendix C, or Appendix D. [...] The cipher suite requirement for clients is weaker than for servers because many clients, such as web browsers, may not allow the same level of configuration as servers. [...] Section 3.3.1:",
                        RequirementLevel.SHOULD,
                        List.of(ProtocolVersion.TLS13),
                        Arrays.asList(
                                CipherSuite.TLS_AES_128_GCM_SHA256,
                                CipherSuite.TLS_AES_256_GCM_SHA384,
                                CipherSuite.TLS_AES_128_CCM_SHA256,
                                CipherSuite.TLS_AES_128_CCM_8_SHA256)));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "The client should not be configured to use cipher suites other than those listed in Section 3.3.1, Appendix C, or Appendix D. [...] The cipher suite requirement for clients is weaker than for servers because many clients, such as web browsers, may not allow the same level of configuration as servers. [...] Appendix C—Pre-shared Keys:",
                        RequirementLevel.SHOULD,
                        Arrays.asList(
                                ProtocolVersion.TLS10,
                                ProtocolVersion.TLS11,
                                ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                                CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_PSK_WITH_AES_128_CCM,
                                CipherSuite.TLS_PSK_WITH_AES_256_CCM,
                                CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                                CipherSuite.TLS_PSK_WITH_AES_256_CCM_8,
                                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
                                CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA,
                                CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA)));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "Appendix D—RSA Key Transport: While these guidelines do not recommend cipher suites using RSA key transport, there may be circumstances in practice where RSA key transport is needed. [...] If RSA key transport is needed while a new traffic inspection strategy is being developed, only RSA key transport cipher suites from the following list may be used.",
                        RequirementLevel.MAY,
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
                                CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384)));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS implementations that support versions prior to TLS 1.3 shall use the bad_record_mac error to indicate a padding error. Implementations shall compute the MAC regardless of whether padding errors exist. TLS implementations should support constant-time decryption or near constant-time decryption.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The validated random number generator should be used to generate the 4-byte timestamp of the client random value for TLS versions prior to TLS 1.3.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use the Renegotiation Indication extension.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the Server Name Indication extension.",
                        RequirementLevel.MUST,
                        ExtensionType.SERVER_NAME_INDICATION));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use the Extended Master Secret extension.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The client shall be configured to use the Signature Algorithms extension.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.TRUE))),
                        ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The client shall be configured to use the Certificate Status Request extension.",
                        RequirementLevel.MUST,
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
                        TestResults.TRUE));
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
                new ExtensionGuidelineCheck(
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
                        ExtensionType.ELLIPTIC_CURVES));
        checks.add(
                new NamedGroupsGuidelineCheck(
                        "When elliptic curve cipher suites are configured, at least one of the NIST-approved curves, P-256 (secp256r1) and P-384 (secp384r1), shall be supported as described in RFC 8422. Additional NIST-recommended elliptic curves are listed in SP 800-56A, Appendix D. Finite field groups that are approved for TLS in SP 800-56A, Appendix D may be supported.",
                        RequirementLevel.MUST,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_ECDHE,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.TRUE))),
                        Arrays.asList(
                                NamedGroup.SECP224R1,
                                NamedGroup.SECP256R1,
                                NamedGroup.SECP384R1,
                                NamedGroup.SECP521R1,
                                NamedGroup.SECT233K1,
                                NamedGroup.SECT283K1,
                                NamedGroup.SECT409K1,
                                NamedGroup.SECT571K1,
                                NamedGroup.SECT233R1,
                                NamedGroup.SECT283R1,
                                NamedGroup.SECT409R1,
                                NamedGroup.SECT571R1,
                                NamedGroup.FFDHE2048,
                                NamedGroup.FFDHE3072,
                                NamedGroup.FFDHE4096,
                                NamedGroup.FFDHE6144,
                                NamedGroup.FFDHE8192),
                        Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1),
                        false,
                        2));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Key Share extension shall be supported if the client supports TLS 1.3.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
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
                                        GuidelineCheckCondition.or(
                                                Arrays.asList(
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty
                                                                        .SUPPORTS_STATIC_ECDH,
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty.SUPPORTS_ECDHE,
                                                                TestResults.TRUE))))),
                        ExtensionType.EC_POINT_FORMATS));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "The Multiple Certificate Status extension should be enabled if the extension is supported by the client implementation.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2,
                        TestResults.TRUE));
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
                                                TlsAnalyzedProperty.SUPPORTS_CBC,
                                                TestResults.TRUE))),
                        TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Pre-Shared Key extension may be supported by TLS 1.3 clients.",
                        RequirementLevel.MAY,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        ExtensionType.PRE_SHARED_KEY));
        // TODO: Implement clientscanner probe that sets
        // TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES.
        //        checks.add(
        //                new AnalyzedPropertyGuidelineCheck(
        //                        "The Pre-Shared Key Exchange Modes extension shall be supported by
        // TLS 1.3 clients that support the Pre-Shared Key extension.",
        //                        RequirementLevel.MUST,
        //                        GuidelineCheckCondition.and(
        //                                Arrays.asList(
        //                                        GuidelineCheckCondition.or(
        //                                                Arrays.asList(
        //                                                        new GuidelineCheckCondition(
        //                                                                TlsAnalyzedProperty
        //
        // .SUPPORTS_TLS13_PSK,
        //                                                                TestResults.TRUE),
        //                                                        new GuidelineCheckCondition(
        //                                                                TlsAnalyzedProperty
        //
        // .SUPPORTS_TLS13_PSK_DHE,
        //                                                                TestResults.TRUE))),
        //                                        new GuidelineCheckCondition(
        //                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
        //                                                TestResults.TRUE))),
        //                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES,
        //                        TestResults.TRUE));
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
                        "The Certificate Signature Algorithms Extension shall be supported if the client supports TLS 1.3.",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        ExtensionType.SIGNATURE_ALGORITHMS_CERT));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Certificate Signature Algorithms Extension should be supported for TLS 1.2.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                                                TestResults.FALSE))),
                        ExtensionType.SIGNATURE_ALGORITHMS_CERT));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Post-handshake Client Authentication extension may be supported if the client supports TLS 1.3.",
                        RequirementLevel.MAY,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        ExtensionType.POST_HANDSHAKE_AUTH));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Client Certificate URL extension should not be supported.",
                        RequirementLevel.SHOULD_NOT,
                        GuidelineCheckCondition.or(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                                                TestResults.TRUE),
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE))),
                        false,
                        ExtensionType.CLIENT_CERTIFICATE_URL));
        checks.add(
                new ExtensionGuidelineCheck(
                        "The Early Data Indication extension should not be used.",
                        RequirementLevel.SHOULD_NOT,
                        false,
                        ExtensionType.EARLY_DATA));
        checks.add(
                new ExtensionGuidelineCheck( // Raw Public Key is currently the only use-case for
                        // client/server certificate type. Thus, it is
                        // sufficient to just check if any of these extensions
                        // is present in the ClientHello.
                        "The Raw Public Key extension shall not be supported.",
                        RequirementLevel.MUST_NOT,
                        false,
                        ExtensionType.CLIENT_CERTIFICATE_TYPE,
                        ExtensionType.SERVER_CERTIFICATE_TYPE));

        // TODO: Add Check for "4.5.3 Checking the Server Key Size". Probably can utilize
        // ServerCertificateKeySizeProbe.java once its executeTest() is implemented.

        // TODO: Implement clientscanner probe that sets TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT.
        //        checks.add(
        //                new AnalyzedPropertyGuidelineCheck(
        //                        "Clients using TLS 1.3 should not send 0-RTT data.",
        //                        RequirementLevel.SHOULD_NOT,
        //                        new GuidelineCheckCondition(
        //                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
        //                        TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT,
        //                        TestResults.FALSE));
        // TODO: Implement clientscanner probe that sets
        // TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START.
        //        checks.add(
        //                new AnalyzedPropertyGuidelineCheck(
        //                        "TLS 1.2 clients shall not use False Start.",
        //                        RequirementLevel.MUST_NOT,
        //                        new GuidelineCheckCondition(
        //                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
        //                        TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START,
        //                        TestResults.FALSE));
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
