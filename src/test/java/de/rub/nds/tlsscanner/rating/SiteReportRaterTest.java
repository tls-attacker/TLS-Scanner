/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import org.junit.Test;
import static org.junit.Assert.*;

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
    
}
