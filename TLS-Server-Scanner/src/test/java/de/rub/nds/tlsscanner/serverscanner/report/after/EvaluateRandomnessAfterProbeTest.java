/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;

/**
 * Test-Class for EvaluateRandomnessAfterProbe.java, which currently analyzes a site-report, examines all random-values
 * extracted by the RandomnessExtractor, filters the messages for messages which are not resend-requests by the Server
 * and then checks if all extracted random-values are different or equal.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class EvaluateRandomnessAfterProbeTest {

    private RandomnessAfterProbe evaluator;

    @SuppressWarnings("SpellCheckingInspection")
    private final static byte[] STATIC_RANDOM1 =
        ArrayConverter.hexStringToByteArray("4DDE56987D18EF88F94030A808800DC680BBFD3B9D6B9B522E8339053DC2EDEE");
    private final static byte[] STATIC_RANDOM2 =
        ArrayConverter.hexStringToByteArray("CC4DC97612BDB5DA500D45B69B9F4FD8D1B449AD9FDD509DA7DC95F8077CDA7B");
    private final static byte[] STATIC_RANDOM3 =
        ArrayConverter.hexStringToByteArray("B1BA2D91193EF3448F33B5BEB0D5D31C78A3E5242896B9E539FDE578D2AAB2BC");
    private final static byte[] HELLO_RETRY_REQUEST_CONST =
        ArrayConverter.hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
    private final Logger LOGGER = LogManager.getLogger();

    public EvaluateRandomnessAfterProbeTest() {
    }

    /**
     * Helper-Method for generating SiteReports with provided random-bytes.
     * 
     * @param  randomBytes
     *                     byte-arrays providing the random-bytes. If no argument is provided, an empty SiteReport is
     *                     generated
     * @return             a SiteReport filled with the provided random-bytes
     */
    private SiteReport generateSiteReport(byte[]... randomBytes) {
        SiteReport generatedReport = new SiteReport("test", 443);

        ExtractedValueContainer extractedValueContainer = new ExtractedValueContainer(TrackableValueType.RANDOM);
        Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap = new HashMap<>();

        if (randomBytes.length == 0) {
            // return empty SiteReport
            extractedValueContainerMap.put(TrackableValueType.RANDOM, extractedValueContainer);
            generatedReport.setExtractedValueContainerList(extractedValueContainerMap);
            return generatedReport;
        }

        for (byte[] random : randomBytes) {
            ComparableByteArray generatedRandom = new ComparableByteArray(random);
            extractedValueContainer.put(generatedRandom);
        }

        extractedValueContainerMap.put(TrackableValueType.RANDOM, extractedValueContainer);
        generatedReport.setExtractedValueContainerList(extractedValueContainerMap);

        return generatedReport;
    }

    @Before
    public void setUp() {
        evaluator = new RandomnessAfterProbe();
    }
}
