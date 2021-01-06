/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.serverscanner.constants.RandomType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

import java.util.LinkedList;

/***
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngAfterProbeTest {

    private SiteReport testReport;
    private TlsRngAfterProbe randomnessTester;

    public TlsRngAfterProbeTest() {
    }

    @Before
    public void setUp() {
        randomnessTester = new TlsRngAfterProbe();
        testReport = new SiteReport("test");
    }

    private void generateDuplicateRandom(RandomType duplicateForType) {
        if (duplicateForType == RandomType.RANDOM) {
            LinkedList<ComparableByteArray> randoms = new LinkedList<>();
            byte[] random = ArrayConverter
                    .hexStringToByteArray("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
            ComparableByteArray convertedRandom = new ComparableByteArray(random);
            randoms.add(convertedRandom);
            randoms.add(convertedRandom);
            testReport.setExtractedRandomList(randoms);
        }
        if (duplicateForType == RandomType.SESSION_ID) {
            LinkedList<ComparableByteArray> sessionIds = new LinkedList<>();
            byte[] sessionID = ArrayConverter
                    .hexStringToByteArray("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
            ComparableByteArray convertedSessionId = new ComparableByteArray(sessionID);
            sessionIds.add(convertedSessionId);
            sessionIds.add(convertedSessionId);
            testReport.setExtractedSessionIDList(sessionIds);
        }
        if (duplicateForType == RandomType.IV) {
            LinkedList<ComparableByteArray> iVs = new LinkedList<>();
            byte[] iV = ArrayConverter.hexStringToByteArray("AABBCCDDEEFFAABBCCDDEEFFAABBCCDD");
            ComparableByteArray convertedIv = new ComparableByteArray(iV);
            iVs.add(convertedIv);
            iVs.add(convertedIv);
            testReport.setExtractedIVList(iVs);
        }
    }

    @Test
    public void testDuplicateDetection() {
        testReport.putResult(AnalyzedProperty.RNG_EXTRACTED, TestResult.TRUE);

        generateDuplicateRandom(RandomType.RANDOM);
        testReport.setExtractedSessionIDList(new LinkedList<>());
        testReport.setExtractedIVList(new LinkedList<>());
        randomnessTester.analyze(testReport);
        assertTrue(testReport.getRandomDuplicatesResult().contains(RandomType.RANDOM));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.IV));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.SESSION_ID));

        generateDuplicateRandom(RandomType.SESSION_ID);
        testReport.setExtractedRandomList(new LinkedList<>());
        testReport.setExtractedIVList(new LinkedList<>());
        randomnessTester.analyze(testReport);
        assertTrue(testReport.getRandomDuplicatesResult().contains(RandomType.SESSION_ID));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.RANDOM));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.IV));

        generateDuplicateRandom(RandomType.IV);
        testReport.setExtractedRandomList(new LinkedList<>());
        testReport.setExtractedSessionIDList(new LinkedList<>());
        randomnessTester.analyze(testReport);
        assertTrue(testReport.getRandomDuplicatesResult().contains(RandomType.IV));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.RANDOM));
        assertFalse(testReport.getRandomDuplicatesResult().contains(RandomType.SESSION_ID));

    }

}
