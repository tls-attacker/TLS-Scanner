/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.GuidelineReport;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.passive.TrackableValue;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.CipherSuiteOrderProbe;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
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

        ServerReportSerializer.serialize(new ByteArrayOutputStream(), report);
        // This should not throw an exception
    }
}
