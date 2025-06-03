/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.serialization;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.SignatureAndHashAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class BsiGuidelineSerializationIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void serialize() throws JAXBException, IOException {
        List<GuidelineCheck<ClientReport>> checks = new ArrayList<>();

        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Grundsätzlich werden TLS 1.2 und TLS 1.3 empfohlen.",
                        RequirementLevel.SHOULD,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Grundsätzlich werden TLS 1.2 und TLS 1.3 empfohlen.",
                        RequirementLevel.SHOULD,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS 1.0 und TLS 1.1 werden nicht empfohlen.",
                        RequirementLevel.SHOULD_NOT,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "TLS 1.0 und TLS 1.1 werden nicht empfohlen.",
                        RequirementLevel.SHOULD_NOT,
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "SSL v2 und SSL v3 werden nicht empfohlen.",
                        RequirementLevel.SHOULD_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "SSL v2 und SSL v3 werden nicht empfohlen.",
                        RequirementLevel.SHOULD_NOT,
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        TestResults.FALSE));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "Grundsätzlich wird empfohlen, nur Cipher-Suiten einzusetzen, die die Anforderungen an die Algorithmen und Schlüssellängen der [TR-02102-1] erfüllen.",
                        RequirementLevel.SHOULD,
                        List.of(ProtocolVersion.TLS12),
                        Arrays.asList(
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM,
                                CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
                                CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384)));
        checks.add(
                new ExtensionGuidelineCheck(
                        "Die Verwendung der \"supported_groups\" Erweiterung für TLS_(EC)DHE_* Cipher-Suiten wird empfohlen.",
                        RequirementLevel.SHOULD,
                        GuidelineCheckCondition.and(
                                Arrays.asList(
                                        new GuidelineCheckCondition(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                                                TestResults.TRUE),
                                        GuidelineCheckCondition.or(
                                                Arrays.asList(
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty.SUPPORTS_DHE,
                                                                TestResults.TRUE),
                                                        new GuidelineCheckCondition(
                                                                TlsAnalyzedProperty.SUPPORTS_ECDHE,
                                                                TestResults.TRUE))))),
                        ExtensionType.ELLIPTIC_CURVES));
        checks.add(
                new NamedGroupsGuidelineCheck(
                        "Die folgenden Diffie-Hellman Gruppen werden empfohlen.",
                        RequirementLevel.SHOULD,
                        Arrays.asList(
                                NamedGroup.SECP256R1,
                                NamedGroup.SECP384R1,
                                NamedGroup.SECP521R1,
                                NamedGroup.BRAINPOOLP256R1,
                                NamedGroup.BRAINPOOLP384R1,
                                NamedGroup.BRAINPOOLP512R1,
                                NamedGroup.FFDHE3072,
                                NamedGroup.FFDHE4096),
                        Collections.emptyList(),
                        false,
                        2));
        checks.add(
                new ExtensionGuidelineCheck(
                        "Die Verwendung der \"signature_algorithms\" Erweiterung wird empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS));
        checks.add(
                new SignatureAlgorithmsGuidelineCheck(
                        "Die folgenden Signaturverfahren werden empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        Arrays.asList(
                                SignatureAlgorithm.RSA_PKCS1,
                                SignatureAlgorithm.RSA_SSA_PSS,
                                SignatureAlgorithm.DSA,
                                SignatureAlgorithm.ECDSA)));
        checks.add(
                new HashAlgorithmsGuidelineCheck(
                        "Die folgenden Hashfunktionen werden empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        Arrays.asList(
                                HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512)));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Es wird empfohlen Session Renegotiation nur auf Basis von [RFC 5746] zu verwenden.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck( // TODO: ExtensionGuidelineCheck does not work for
                        // *_NOT because it checks if the provided Extension is
                        // set.
                        "Die in [RFC 6066] definierte Extension \"truncated_hmac\" zur Verkürzung der Ausgabe des HMAC auf 80 Bit sollte nicht verwendet werden.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        ExtensionType.TRUNCATED_HMAC));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Es wird empfohlen die TLS-Datenkompression nicht zu verwenden.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Der Einsatz der TLS-Erweiterung \"Encrypt-then-MAC\" gemäß [RFC 7366] wird empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                        TestResults.TRUE));
        checks.add(
                new ExtensionGuidelineCheck( // TODO: ExtensionGuidelineCheck does not work for
                        // *_NOT because it checks if the provided Extension is
                        // set.
                        "Es wird empfohlen, die Heartbeat-Erweiterung nicht zu verwenden.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        ExtensionType.HEARTBEAT));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Der Einsatz der TLS-Erweiterung Extended Master Secret gemäß [RFC 7627] wird empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                        TestResults.TRUE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Der PSK-Modus psk_ke bietet keine Perfect Forward Secrecy. Dieser Modus sollte daher nur in speziellen Anwendungsfällen nach Hinzuziehen eines Experten eingesetzt werden.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Das Senden oder Annehmen von 0-RTT Daten wird nicht empfohlen.",
                        RequirementLevel.SHOULD_NOT,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT,
                        TestResults.FALSE));
        checks.add(
                new NamedGroupsGuidelineCheck(
                        "Die folgenden Diffie-Hellman Gruppen werden empfohlen.",
                        RequirementLevel.SHOULD,
                        Arrays.asList(
                                NamedGroup.SECP256R1,
                                NamedGroup.SECP384R1,
                                NamedGroup.SECP521R1,
                                NamedGroup.BRAINPOOLP256R1,
                                NamedGroup.BRAINPOOLP384R1,
                                NamedGroup.BRAINPOOLP512R1,
                                NamedGroup.FFDHE3072,
                                NamedGroup.FFDHE4096),
                        Collections.emptyList(),
                        true,
                        2));
        checks.add(
                new SignatureAndHashAlgorithmsGuidelineCheck(
                        "Die folgenden Signaturverfahren werden für die \"signature_algorithms\" Erweiterung empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        Arrays.asList(
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512,
                                SignatureAndHashAlgorithm.ECDSA_SHA256,
                                SignatureAndHashAlgorithm.ECDSA_SHA384,
                                SignatureAndHashAlgorithm.ECDSA_SHA512,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P256R1_TLS13_SHA256,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P384R1_TLS13_SHA384,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P512R1_TLS13_SHA512),
                        true));
        checks.add(
                new SignatureAndHashAlgorithmsCertificateGuidelineCheck(
                        "Die folgenden Algorithmen werden für die \"signature_algorithms_cert\" Erweiterung empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        Arrays.asList(
                                SignatureAndHashAlgorithm.RSA_SHA256,
                                SignatureAndHashAlgorithm.RSA_SHA384,
                                SignatureAndHashAlgorithm.RSA_SHA512,
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                                SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384,
                                SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512,
                                SignatureAndHashAlgorithm.ECDSA_SHA256,
                                SignatureAndHashAlgorithm.ECDSA_SHA384,
                                SignatureAndHashAlgorithm.ECDSA_SHA512,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P256R1_TLS13_SHA256,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P384R1_TLS13_SHA384,
                                SignatureAndHashAlgorithm.ECDSA_BRAINPOOL_P512R1_TLS13_SHA512)));
        checks.add(
                new CipherSuiteGuidelineCheck(
                        "Die folgenden Cipher-Suiten werden empfohlen.",
                        RequirementLevel.SHOULD,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE),
                        List.of(ProtocolVersion.TLS13),
                        Arrays.asList(
                                CipherSuite.TLS_AES_128_GCM_SHA256,
                                CipherSuite.TLS_AES_256_GCM_SHA384,
                                CipherSuite.TLS_AES_128_CCM_SHA256)));
        checks.add(
                new KeySizeCertGuidelineCheck(
                        "Es wird empfohlen, mindestens die folgenden Schlüssellängen zu verwenden.",
                        RequirementLevel.SHOULD,
                        3000,
                        3000,
                        250,
                        3000));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Ephemer- bzw. Sitzungsschlüssel dürfen nur für eine Verbindung benutzt werden. (DHE)",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_DHE, TestResults.TRUE),
                        TlsAnalyzedProperty.REUSES_DH_PUBLICKEY,
                        TestResults.FALSE));
        checks.add(
                new AnalyzedPropertyGuidelineCheck(
                        "Ephemer- bzw. Sitzungsschlüssel dürfen nur für eine Verbindung benutzt werden. (ECDHE)",
                        RequirementLevel.MUST,
                        new GuidelineCheckCondition(
                                TlsAnalyzedProperty.SUPPORTS_ECDHE, TestResults.TRUE),
                        TlsAnalyzedProperty.REUSES_EC_PUBLICKEY,
                        TestResults.FALSE));

        Guideline<ClientReport> guideline =
                new Guideline<>(
                        "BSI TR-02102-2 (v2025-01)",
                        "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102-2.html",
                        checks);
        GuidelineIO guidelineIO = new GuidelineIO(TlsAnalyzedProperty.class);
        guidelineIO.write(Paths.get("src/main/resources/guideline/bsi.xml").toFile(), guideline);
    }
}
