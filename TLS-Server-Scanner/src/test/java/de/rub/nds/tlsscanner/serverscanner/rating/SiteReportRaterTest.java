/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import java.util.HashMap;
import static org.junit.Assert.*;
import org.junit.Test;

public class SiteReportRaterTest {

    public SiteReportRaterTest() {
    }

    /**
     * Test of getSiteReportRater method, of class SiteReportRater.
     */
    @Test
    public void testGetSiteReportRater() throws Exception {
        SiteReportRater rater = SiteReportRater.getSiteReportRater("en");
        assertNotNull(rater);
        assertFalse(rater.getRecommendations().getRecommendations().isEmpty());
    }

    @Test
    public void testGetScoreReport() throws Exception {
        HashMap<String, TestResult> resultMap = new HashMap<>();
        resultMap.put(AnalyzedProperty.SUPPORTS_SSL_2.toString(), TestResult.FALSE);
        resultMap.put(AnalyzedProperty.SUPPORTS_SSL_3.toString(), TestResult.TRUE);
        resultMap.put(AnalyzedProperty.SUPPORTS_TLS_1_0.toString(), TestResult.TRUE);

        SiteReportRater rater = SiteReportRater.getSiteReportRater("en");
        ScoreReport report = rater.getScoreReport(resultMap);

        assertEquals(3, report.getInfluencers().size());
    }
}
