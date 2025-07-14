/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CertificateAgilityGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteOrderProbe;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ServerReportJsonMapperTest {

    private ServerReportJsonMapper reportJsonMapper;

    @BeforeEach
    public void setUp() {
        reportJsonMapper = new ServerReportJsonMapper();
    }

    @Test
    void testFromJsonString() throws Exception {
        // Read the report.json from test resources
        Path reportPath = Paths.get(getClass().getClassLoader().getResource("report.json").toURI());
        String jsonReport = Files.readString(reportPath);

        // Test conversion from JSON string to ServerReport
        ServerReport result = reportJsonMapper.fromJsonString(jsonReport);

        // Verify the result is not null and has expected properties
        assertNotNull(result);
        // Update assertions based on the actual content of report.json
        assertNotNull(result.getHost());
        assertNotNull(result.getSupportedNamedGroups());
        // Add more specific assertions based on the known content of report.json
    }

    @Test
    void testFromJsonString_Null() {
        // Test conversion with null JSON string
        ServerReport result = reportJsonMapper.fromJsonString(null);

        // Verify null was returned
        assertNull(result);
    }

    @Test
    void testFromJsonString_Empty() {
        // Test conversion with empty JSON string
        ServerReport result = reportJsonMapper.fromJsonString("");

        // Verify null was returned
        assertNull(result);
    }

    @Test
    void testToJsonNode() {
        // Create a real ServerReport as mocks can't be reliably serialized
        ServerReport realReport = new ServerReport("example.com", 443);
        realReport.setServerIsAlive(true);
        // Set some unique identifier to verify round trip
        long currentTime = System.currentTimeMillis();
        realReport.setScanStartTime(currentTime);
        realReport.putResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, TestResults.TRUE);

        // Convert to JSON node
        ObjectNode jsonNode = reportJsonMapper.toJsonNode(realReport);

        // Verify JSON node was created correctly
        assertNotNull(jsonNode);
        assertTrue(jsonNode.has("host"));
        assertEquals("example.com", jsonNode.get("host").asText());
    }

    @Test
    void testFromJsonNode() {
        // Create a real ServerReport to convert to JSON node
        ServerReport originalReport = new ServerReport("example.com", 443);
        originalReport.setServerIsAlive(true);
        long currentTime = System.currentTimeMillis();
        originalReport.setScanStartTime(currentTime);
        originalReport.putResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, TestResults.TRUE);

        // Convert to JSON node
        ObjectNode jsonNode = reportJsonMapper.toJsonNode(originalReport);

        // Convert back to ServerReport
        ServerReport result = reportJsonMapper.fromJsonNode(jsonNode);

        // Verify round trip conversion preserved data
        assertNotNull(result);
        assertEquals("example.com", result.getHost());
        assertEquals(currentTime, result.getScanStartTime());
        assertTrue(result.getServerIsAlive());
        assertEquals(TestResults.TRUE, result.getResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE));
    }

    @Test
    void testSerializeEmptyReport() {
        // Create an empty report
        ServerReport emptyReport = new ServerReport();

        // Test serialization to JSON string
        String jsonString = reportJsonMapper.toJsonString(emptyReport);
        assertNotNull(jsonString);

        // Test serialization to JSON node
        ObjectNode jsonNode = reportJsonMapper.toJsonNode(emptyReport);
        assertNotNull(jsonNode);

        // Deserialize back and ensure we can handle empty reports
        ServerReport deserializedReport = reportJsonMapper.fromJsonString(jsonString);
        assertNotNull(deserializedReport);
    }

    @Test
    void testSerializeFullReport() {
        // Create a complex report with many fields populated, similar to ServerReportSerializerTest
        ServerReport report = createComplexServerReport();

        // Convert to JSON string
        String jsonString = reportJsonMapper.toJsonString(report);
        assertNotNull(jsonString);

        // Deserialize from JSON string
        ServerReport deserializedReport = reportJsonMapper.fromJsonString(jsonString);
        assertNotNull(deserializedReport);

        // Verify basic properties are preserved
        assertEquals(report.getHost(), deserializedReport.getHost());
        assertEquals(report.getScanStartTime(), deserializedReport.getScanStartTime());
        assertEquals(report.getScanEndTime(), deserializedReport.getScanEndTime());
        assertEquals(report.getServerIsAlive(), deserializedReport.getServerIsAlive());
        assertEquals(report.getIsHandshaking(), deserializedReport.getIsHandshaking());
        assertEquals(
                report.getPerformedConnections(), deserializedReport.getPerformedConnections());
        assertEquals(report.getScore(), deserializedReport.getScore());
        assertEquals(report.getSpeaksProtocol(), deserializedReport.getSpeaksProtocol());

        // Check configuration profile identifiers
        assertEquals(
                report.getConfigProfileIdentifier(),
                deserializedReport.getConfigProfileIdentifier());
        assertEquals(
                report.getConfigProfileIdentifierTls13(),
                deserializedReport.getConfigProfileIdentifierTls13());

        // Check specific score report properties including influencer values
        assertNotNull(deserializedReport.getScoreReport());
        assertNotNull(deserializedReport.getScoreReport().getInfluencers());

        // Verify the score report has at least one influencer
        assertNotNull(deserializedReport.getScoreReport());
        assertNotNull(deserializedReport.getScoreReport().getInfluencers());
        assertTrue(deserializedReport.getScoreReport().getInfluencers().size() > 0);

        // Check that probe lists exist
        assertNotNull(deserializedReport.getExecutedProbes());
        assertNotNull(deserializedReport.getUnexecutedProbes());

        // Check guideline reports
        assertNotNull(deserializedReport.getGuidelineReports());
        assertEquals(1, deserializedReport.getGuidelineReports().size());
        assertEquals("guideline", deserializedReport.getGuidelineReports().get(0).getName());
        assertEquals("here is a link", deserializedReport.getGuidelineReports().get(0).getLink());
        // Access check results correctly with getResults() method
        List<GuidelineCheckResult> checkResults =
                deserializedReport.getGuidelineReports().get(0).getResults();
        assertNotNull(checkResults);
        assertEquals(1, checkResults.size());
        assertEquals(GuidelineAdherence.ADHERED, checkResults.get(0).getAdherence());

        // Check performance data
        assertNotNull(deserializedReport.getProbePerformanceData());
        assertTrue(
                deserializedReport.getProbePerformanceData().stream()
                        .anyMatch(p -> p.getType() == TlsProbeType.ALPN));

        // Check certificate data
        ListResult<?> certificateChainsResult =
                (ListResult<?>)
                        deserializedReport.getResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS);
        assertNotNull(certificateChainsResult);
        assertEquals(1, certificateChainsResult.getList().size());

        Object firstCertReport = certificateChainsResult.getList().get(0);
        assertTrue(firstCertReport instanceof CertificateReport);
        CertificateReport deserializedCertReport = (CertificateReport) firstCertReport;

        // Verify certificate report fields
        assertEquals("test", deserializedCertReport.getIssuer());
        assertEquals("hello", deserializedCertReport.getSubject());
        assertEquals(X509Version.V2, deserializedCertReport.getVersion());
        assertEquals(HashAlgorithm.GOST_R3411_12, deserializedCertReport.getHashAlgorithm());
        assertEquals(SignatureAlgorithm.ED448, deserializedCertReport.getSignatureAlgorithm());
        assertEquals(
                X509SignatureAlgorithm.ECDSA_WITH_SHA384,
                deserializedCertReport.getX509SignatureAlgorithm());
        assertEquals(X509NamedCurve.BRAINPOOLP160R1, deserializedCertReport.getNamedCurve());
        assertEquals("thisisthepin", deserializedCertReport.getSha256Pin());
        assertTrue(deserializedCertReport.getLeafCertificate());
        assertTrue(deserializedCertReport.getSelfSigned());

        // Convert to JSON node
        ObjectNode jsonNode = reportJsonMapper.toJsonNode(report);
        assertNotNull(jsonNode);

        // Deserialize from JSON node
        ServerReport nodeDeserializedReport = reportJsonMapper.fromJsonNode(jsonNode);
        assertNotNull(nodeDeserializedReport);

        // Verify key properties are preserved in node deserialization
        assertEquals(report.getHost(), nodeDeserializedReport.getHost());
        assertEquals(report.getScanStartTime(), nodeDeserializedReport.getScanStartTime());
        assertEquals(report.getScanEndTime(), nodeDeserializedReport.getScanEndTime());
        assertEquals(
                report.getConfigProfileIdentifier(),
                nodeDeserializedReport.getConfigProfileIdentifier());
        assertEquals(report.getScore(), nodeDeserializedReport.getScore());

        // Verify guideline reports survived node serialization
        assertNotNull(nodeDeserializedReport.getGuidelineReports());
        assertEquals(1, nodeDeserializedReport.getGuidelineReports().size());

        // Verify certificate data survived node serialization
        ListResult<?> nodeCertificateChainsResult =
                (ListResult<?>)
                        nodeDeserializedReport.getResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS);
        assertNotNull(nodeCertificateChainsResult);
        assertEquals(1, nodeCertificateChainsResult.getList().size());
    }

    @Test
    void testCompleteRoundTripScenario() {
        // Create a real ServerReport with realistic data
        ServerReport originalReport = new ServerReport("example.com", 443);
        originalReport.setServerIsAlive(true);
        long scanStartTime = System.currentTimeMillis() - 5000; // 5 seconds ago
        long scanEndTime = System.currentTimeMillis();
        originalReport.setScanStartTime(scanStartTime);
        originalReport.setScanEndTime(scanEndTime);
        originalReport.putResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, TestResults.TRUE);
        originalReport.putResult(
                TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH, TestResults.FALSE);

        // 1. Convert to JSON string
        String jsonString = reportJsonMapper.toJsonString(originalReport);
        assertNotNull(jsonString);
        assertTrue(jsonString.contains("example.com"));

        // 2. Convert back to ServerReport
        ServerReport resultFromString = reportJsonMapper.fromJsonString(jsonString);
        assertNotNull(resultFromString);
        assertEquals("example.com", resultFromString.getHost());
        assertEquals(scanStartTime, resultFromString.getScanStartTime());
        assertEquals(scanEndTime, resultFromString.getScanEndTime());
        assertEquals(
                TestResults.TRUE,
                resultFromString.getResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE));
        assertEquals(
                TestResults.FALSE,
                resultFromString.getResult(
                        TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH));

        // 3. Convert to JSON node
        ObjectNode jsonNode = reportJsonMapper.toJsonNode(originalReport);
        assertNotNull(jsonNode);

        // 4. Convert back to ServerReport from node
        ServerReport resultFromNode = reportJsonMapper.fromJsonNode(jsonNode);
        assertNotNull(resultFromNode);
        assertEquals("example.com", resultFromNode.getHost());
        assertEquals(scanStartTime, resultFromNode.getScanStartTime());
        assertEquals(
                TestResults.TRUE,
                resultFromNode.getResult(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE));
        assertEquals(
                TestResults.FALSE,
                resultFromNode.getResult(
                        TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH));
    }

    /**
     * Helper method to create a complex ServerReport with many fields populated. This is similar to
     * the test report created in ServerReportSerializerTest.
     */
    private ServerReport createComplexServerReport() {
        // Create a score report
        ScoreReport scoreReport = new ScoreReport(5, new HashMap<>());
        scoreReport
                .getInfluencers()
                .put(
                        TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE,
                        new PropertyResultRatingInfluencer(TestResults.CANNOT_BE_TESTED, 10));

        // Create a guideline report
        List<GuidelineCheckResult> checkResultList = new LinkedList<>();
        checkResultList.add(
                new CertificateAgilityGuidelineCheckResult(
                        "some check", GuidelineAdherence.ADHERED));
        GuidelineReport guidelineReport =
                new GuidelineReport("guideline", "here is a link", checkResultList);

        // Create a certificate report
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

        // Create a certificate chain report
        CertificateChainReport chainReport =
                new CertificateChainReport(new X509CertificateChain(), "test");

        // Create and populate the server report
        ServerReport report = new ServerReport("complex.example.com", 443);
        report.setConfigProfileIdentifier("something");
        report.setScanEndTime(1000L);
        report.setScanStartTime(0L);
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
                TrackableValueType.COOKIE, new ExtractedValueContainer<byte[]>());
        report.putResult(
                TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE,
                new ListResult<>(TlsAnalyzedProperty.CERTIFICATE_CHAINS, List.of(chainReport)));
        report.putResult(
                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                new ListResult<>(TlsAnalyzedProperty.CERTIFICATE_CHAINS, List.of(certReport)));

        return report;
    }
}
