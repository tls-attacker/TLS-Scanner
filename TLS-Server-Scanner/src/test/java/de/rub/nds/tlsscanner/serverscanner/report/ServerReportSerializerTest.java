/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.passive.TrackableValue;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteOrderProbe;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.jupiter.api.Test;

public class ServerReportSerializerTest {

    @Test
    void testSerializeEmpty() {
        ServerReport report = new ServerReport();
        ServerReportSerializer.serialize(new ByteArrayOutputStream(), report);
        // This should not throw an exception
    }

    @Test
    void testSerializeFullReport() {
        ScoreReport scoreReport = new ScoreReport(5, new HashMap<>());
        scoreReport
                .getInfluencers()
                .put(
                        TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE,
                        new PropertyResultRatingInfluencer(TestResults.CANNOT_BE_TESTED, 10));

        List<GuidelineCheckResult> checkResultList = new LinkedList<>();
        checkResultList.add(new GuidelineCheckResult("some checke", GuidelineAdherence.ADHERED));
        GuidelineReport guidelineReport =
                new GuidelineReport("guideline", "here is a link", checkResultList);

        CertificateReport certReport = new CertificateReport();
        certReport.setAlternativeNames(List.of("value1"));
        certReport.setCertificateTransparency(true);
        certReport.setCrlSupported(true);
        certReport.setCustomTrustAnchor(true);
        certReport.setDnsCAA(true);
        certReport.setExtendedKeyUsagePresent(true);
        certReport.setExtendedKeyUsageServerAuth(true);
        certReport.setExtendedValidation(true);
        certReport.setHashAlgorithm(HashAlgorithm.GOST_R3411_12);
        certReport.setIssuer("test");
        certReport.setKeyUsageSet(Set.of(KeyUsage.CRL_SIGN));
        certReport.setLeafCertificate(true);
        certReport.setNamedCurve(X509NamedCurve.BRAINPOOLP160R1);
        certReport.setNotAfter(new DateTime(12345));
        certReport.setNotBefore(new DateTime(DateTime.now().getMillis() - 1000));
        certReport.setOriginalFullDuration(Duration.standardDays(4));
        certReport.setOcspMustStaple(true);
        certReport.setOcspSupported(false);
        certReport.setPublicKey(new RsaPublicKey(BigInteger.ONE, BigInteger.TEN));
        certReport.setRemainingDuration(Duration.millis(100));
        certReport.setRevoked(false);
        certReport.setRocaVulnerable(false);
        certReport.setSelfSigned(true);
        certReport.setSha256Fingerprint(new byte[] {1, 2, 3});
        certReport.setSha256Pin("thisisthepin");
        certReport.setSignatureAlgorithm(SignatureAlgorithm.ED448);
        certReport.setSignatureAndHashAlgorithmOid(X509SignatureAlgorithm.DSA_WITH_SHA1.getOid());
        certReport.setSubject("hello");
        certReport.setSupportedExtensionTypes(
                List.of(
                        X509ExtensionType.AUTHORITY_INFORMATION_ACCESS,
                        X509ExtensionType.BASIC_CONSTRAINTS));
        certReport.setTrustAnchor(true);
        certReport.setTrusted(true);
        certReport.setVersion(X509Version.V2);
        certReport.setWeakDebianKey(true);
        certReport.setX509SignatureAlgorithm(X509SignatureAlgorithm.ECDSA_WITH_SHA384);

        CertificateChainReport chainReport =
                new CertificateChainReport(new X509CertificateChain(), "test");

        ServerReport report = new ServerReport();
        report.setConfigProfileIdentifier("something");
        report.setScanEndTime(1000);
        report.setScanStartTime(0);
        report.setConfigProfileIdentifierTls13("some identifier");
        report.setIsHandshaking(true);
        report.setPerformedConnections(10);
        report.setScore(5);
        report.setScoreReport(scoreReport);
        report.setServerIsAlive(true);
        report.setSpeaksProtocol(true);
        report.addGuidelineReport(guidelineReport);
        report.markProbeAsExecuted(new CertificateProbe(null, null));
        report.markProbeAsUnexecuted(new CipherSuiteOrderProbe(null, null));
        report.recordProbePerformance(new PerformanceData(TlsProbeType.ALPN, 0, 10));
        report.putExtractedValueContainer(
                new TrackableValue() {}, new ExtractedValueContainer<>(new TrackableValue() {}));
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE,
                new ListResult<>(TlsAnalyzedProperty.CERTIFICATE_CHAINS, List.of(chainReport)));
        report.putResult(
                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                new ListResult<>(TlsAnalyzedProperty.CERTIFICATE_CHAINS, List.of(certReport)));
        ServerReportSerializer.serialize(new ByteArrayOutputStream(), report);
        // This should not throw an exception
    }
}
