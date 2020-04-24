/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Test-Class for EvaluateRandomnessAfterProbe.java, which currently analyzes a site-report, examines all random-values
 * extracted by the RandomnessExtractor, filters the messages for messages which are not resend-requests by the Server
 * and then checks if all extracted random-values are different or equal.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class EvaluateRandomnessAfterProbeTest {

    private final Logger LOGGER = LogManager.getLogger();

    public EvaluateRandomnessAfterProbeTest(){
    }


    @Test
    public void testNoDuplicatesAnalyze(){
    }

    @Test
    public void testDuplicatesAnalyze(){
    }

    @Test
    public void testEmptySideReportAnalyze(){
    }

    @Test
    public void testHelloRetryRequestAnalyze(){
    }

    @Test
    public void testNoExtractedRandomAnalyze(){
    }

}
