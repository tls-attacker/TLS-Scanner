/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.rating.ScoreReport;
import de.rub.nds.scanner.core.report.rating.SiteReportRater;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

public class ServerReportRaterTest {

    public ServerReportRaterTest() {
    }

    /**
     * Test of getSiteReportRater method, of class SiteReportRater.
     */
    @Test
    public void testGetSiteReportRater() throws Exception {
        SiteReportRater rater = DefaultRatingLoader.getServerReportRater("en");
        assertNotNull(rater);
        assertFalse(rater.getRecommendations().getRecommendations().isEmpty());

    }

    @Test
    public void testGetScoreReport() throws Exception {
        HashMap<String, TestResult> resultMap = new HashMap<>();
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_2.toString(), TestResults.FALSE);
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_SSL_3.toString(), TestResults.TRUE);
        resultMap.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0.toString(), TestResults.TRUE);

        SiteReportRater rater = DefaultRatingLoader.getServerReportRater("en");
        ScoreReport report = rater.getScoreReport(resultMap);

        assertEquals(3, report.getInfluencers().size());
    }
}
