/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.CipherSuiteGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.HashAlgorithmsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.NamedGroupsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.SignatureAlgorithmsGuidelineCheckResult;
import java.io.ByteArrayOutputStream;
import java.util.*;
import org.junit.jupiter.api.Test;

public class GuidelineResultSerializationTest {

    @Test
    void testCipherSuiteGuidelineCheckResultSerialization() throws Exception {
        List<CipherSuite> recommendedSuites =
                Arrays.asList(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        List<CipherSuite> notRecommendedSuites =
                Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        CipherSuiteGuidelineCheckResult result =
                new CipherSuiteGuidelineCheckResult(
                        "BSI TR-02102-2 Cipher Suite Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedSuites,
                        recommendedSuites);

        String json = serializeResult(result);

        assertTrue(json.contains("\"recommendedSuites\""));
        assertTrue(json.contains("\"notRecommendedSuites\""));
        assertTrue(json.contains("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"));
        assertTrue(json.contains("TLS_RSA_WITH_AES_128_CBC_SHA"));
    }

    @Test
    void testHashAlgorithmsGuidelineCheckResultSerialization() throws Exception {
        List<HashAlgorithm> recommendedAlgorithms =
                Arrays.asList(HashAlgorithm.SHA256, HashAlgorithm.SHA384);
        Set<HashAlgorithm> notRecommendedAlgorithms =
                new HashSet<>(Collections.singletonList(HashAlgorithm.SHA1));

        HashAlgorithmsGuidelineCheckResult result =
                new HashAlgorithmsGuidelineCheckResult(
                        "Hash Algorithm Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedAlgorithms,
                        recommendedAlgorithms);

        String json = serializeResult(result);

        assertTrue(json.contains("\"recommendedAlgorithms\""));
        assertTrue(json.contains("\"notRecommendedAlgorithms\""));
        assertTrue(json.contains("SHA256"));
        assertTrue(json.contains("SHA1"));
    }

    @Test
    void testNamedGroupsGuidelineCheckResultSerialization() throws Exception {
        List<NamedGroup> recommendedGroups =
                Arrays.asList(NamedGroup.SECP256R1, NamedGroup.SECP384R1);
        Set<NamedGroup> notRecommendedGroups =
                new HashSet<>(Collections.singletonList(NamedGroup.SECP160K1));

        NamedGroupsGuidelineCheckResult result =
                new NamedGroupsGuidelineCheckResult(
                        "Named Groups Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedGroups,
                        recommendedGroups);

        String json = serializeResult(result);

        assertTrue(json.contains("\"recommendedGroups\""));
        assertTrue(json.contains("\"notRecommendedGroups\""));
        assertTrue(json.contains("SECP256R1"));
        assertTrue(json.contains("SECP160K1"));
    }

    @Test
    void testSignatureAlgorithmsGuidelineCheckResultSerialization() throws Exception {
        List<SignatureAlgorithm> recommendedAlgorithms =
                Arrays.asList(SignatureAlgorithm.RSA_PKCS1, SignatureAlgorithm.ECDSA);
        Set<SignatureAlgorithm> notRecommendedAlgorithms =
                new HashSet<>(Collections.singletonList(SignatureAlgorithm.DSA));

        SignatureAlgorithmsGuidelineCheckResult result =
                new SignatureAlgorithmsGuidelineCheckResult(
                        "Signature Algorithm Check",
                        GuidelineAdherence.VIOLATED,
                        notRecommendedAlgorithms,
                        recommendedAlgorithms);

        String json = serializeResult(result);

        assertTrue(json.contains("\"recommendedAlgorithms\""));
        assertTrue(json.contains("\"notRecommendedAlgorithms\""));
        assertTrue(json.contains("RSA_PKCS1"));
        assertTrue(json.contains("DSA"));
    }

    @Test
    void testFullGuidelineReportSerialization() throws Exception {
        List<GuidelineCheckResult> checkResults = new ArrayList<>();

        // Add cipher suite result
        checkResults.add(
                new CipherSuiteGuidelineCheckResult(
                        "Cipher Suite Check",
                        GuidelineAdherence.VIOLATED,
                        Collections.singletonList(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA),
                        Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)));

        // Add hash algorithm result
        checkResults.add(
                new HashAlgorithmsGuidelineCheckResult(
                        "Hash Check",
                        GuidelineAdherence.ADHERED,
                        Collections.emptySet(),
                        Arrays.asList(HashAlgorithm.SHA256)));

        GuidelineReport report =
                new GuidelineReport("BSI TR-02102-2", "https://www.bsi.bund.de/...", checkResults);

        ServerReport serverReport = new ServerReport();
        serverReport.addGuidelineReport(report);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        ServerReportSerializer.serialize(stream, serverReport);
        String json = stream.toString();

        assertTrue(json.contains("\"guidelineReports\""));
        assertTrue(json.contains("\"recommendedSuites\""));
        assertTrue(json.contains("\"recommendedAlgorithms\""));
    }

    private String serializeResult(GuidelineCheckResult result) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.GETTER, Visibility.NONE);
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);

        return mapper.writeValueAsString(result);
    }
}
