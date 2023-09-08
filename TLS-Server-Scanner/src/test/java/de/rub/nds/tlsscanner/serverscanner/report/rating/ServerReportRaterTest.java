/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.HashMap;
import org.junit.jupiter.api.Test;

public class ServerReportRaterTest {

    public ServerReportRaterTest() {}

    /** Test of getSiteReportRater method, of class SiteReportRater. */
    @Test
    public void testGetSiteReportRater() throws Exception {
        SiteReportRater rater = DefaultRatingLoader.getServerReportRater("en");
        assertNotNull(rater);
        assertFalse(rater.getRecommendations().getRecommendations().isEmpty());
    }

    @Test
    public void testGetScoreReport() throws Exception {
        HashMap<AnalyzedProperty, TestResult> resultMap = new HashMap<>();
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.FALSE);
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.TRUE);

        SiteReportRater rater = DefaultRatingLoader.getServerReportRater("en");
        ScoreReport report = rater.getScoreReport(resultMap);

        assertEquals(3, report.getInfluencers().size());
    }
}
