/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ServerRandomnessAfterProbeTest {

    private ServerReport report;
    private ServerRandomnessAfterProbe probe;

    private ExtractedValueContainer<ComparableByteArray> serverRandomContainer;
    private ExtractedValueContainer<ComparableByteArray> cookieContainer;
    private ExtractedValueContainer<ComparableByteArray> sessionIdContainer;
    private ExtractedValueContainer<ComparableByteArray> cbcIVContainer;

    // generates "cryptographically strong random numbers" with constant seed for deterministic
    // tests
    private final SecureRandom secureRandom =
            new SecureRandom(ByteBuffer.allocate(4).putInt(123456).array());
    // generates a single fixed, but "secure" 32 byte sequence over and over again
    private final FixedSecureRandom fixedSecureRandom =
            new FixedSecureRandom(
                    ArrayConverter.hexStringToByteArray(
                            "88fd513f45ae0f96756b0984aa674c607ef076385da9f2b9a8e171087fb1bfca"));

    @BeforeEach
    public void setup() {
        report = new ServerReport();
        probe = new ServerRandomnessAfterProbe();

        serverRandomContainer = new ExtractedValueContainer<>(TrackableValueType.RANDOM);
        cookieContainer = new ExtractedValueContainer<>(TrackableValueType.COOKIE);
        sessionIdContainer = new ExtractedValueContainer<>(TrackableValueType.SESSION_ID);
        cbcIVContainer = new ExtractedValueContainer<>(TrackableValueType.CBC_IV);

        report.putExtractedValueContainer(TrackableValueType.RANDOM, serverRandomContainer);
        report.putExtractedValueContainer(TrackableValueType.COOKIE, cookieContainer);
        report.putExtractedValueContainer(TrackableValueType.SESSION_ID, sessionIdContainer);
        report.putExtractedValueContainer(TrackableValueType.CBC_IV, cbcIVContainer);
    }

    @Test
    public void testDoesNotUseUnixTime() {
        ComparableByteArray beginningOfTime =
                new ComparableByteArray(ByteBuffer.allocate(32).putInt(1).array());
        serverRandomContainer.put(beginningOfTime);
        probe.analyze(report);
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM));

        ComparableByteArray endOfTime =
                new ComparableByteArray(ByteBuffer.allocate(32).putInt(0xFFFFFFFF).array());
        serverRandomContainer = new ExtractedValueContainer<>(TrackableValueType.RANDOM);
        serverRandomContainer.put(endOfTime);
        probe.analyze(report);
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM));
    }

    @Test
    public void testUsesUnixTime() {
        int currentTimeStamp = (int) (System.currentTimeMillis() / 1000);
        ComparableByteArray currentTime =
                new ComparableByteArray(ByteBuffer.allocate(32).putInt(currentTimeStamp).array());
        serverRandomContainer.put(currentTime);
        probe.analyze(report);
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM));
    }

    @Disabled
    @Test
    public void testSecureRandomness() {
        // while this is not strictly validated, the probe recommends at least ~32000 bytes of
        // recorded randomness
        for (int i = 0; i < 1024; i++) {
            serverRandomContainer.put(new ComparableByteArray(secureRandom.generateSeed(32)));
            cookieContainer.put(new ComparableByteArray(secureRandom.generateSeed(32)));
            sessionIdContainer.put(new ComparableByteArray(secureRandom.generateSeed(32)));
            cbcIVContainer.put(new ComparableByteArray(secureRandom.generateSeed(32)));
        }
        probe.analyze(report);

        for (EntropyReport entropyReport : report.getEntropyReports()) {
            assertFalse(entropyReport.isFailedFourierTest());
            assertFalse(entropyReport.isFailedRunsTest());
            assertFalse(entropyReport.isFailedFrequencyTest());
            assertFalse(entropyReport.isFailedLongestRunTest());
            assertFalse(entropyReport.isFailedMonoBitTest());
            assertFalse(entropyReport.isFailedEntropyTest());
        }
    }

    @Test
    public void testRepeatedGoodRandomValues() {
        List<ComparableByteArray> randoms = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            randoms.add(new ComparableByteArray(secureRandom.generateSeed(32)));
        }
        for (int i = 0; i < 5; i++) {
            for (ComparableByteArray random : randoms) {
                serverRandomContainer.put(random);
                cookieContainer.put(random);
                sessionIdContainer.put(random);
                cbcIVContainer.put(random);
            }
        }
        probe.analyze(report);

        // it should be noticed by at least one of the tests
        for (EntropyReport entropyReport : report.getEntropyReports()) {
            assertTrue(
                    entropyReport.isFailedEntropyTest()
                            || entropyReport.isFailedFourierTest()
                            || entropyReport.isFailedFrequencyTest()
                            || entropyReport.isFailedRunsTest()
                            || entropyReport.isFailedLongestRunTest()
                            || entropyReport.isFailedMonoBitTest());
        }
    }

    @Test
    public void testFixedRandomValues() {
        ComparableByteArray random = new ComparableByteArray(fixedSecureRandom.generateSeed(32));
        for (int i = 0; i < 1024; i++) {
            serverRandomContainer.put(random);
            cookieContainer.put(random);
            sessionIdContainer.put(random);
            cbcIVContainer.put(random);
        }
        probe.analyze(report);

        // it should be noticed by at least one of the tests
        for (EntropyReport entropyReport : report.getEntropyReports()) {
            assertTrue(
                    entropyReport.isFailedEntropyTest()
                            || entropyReport.isFailedFourierTest()
                            || entropyReport.isFailedFrequencyTest()
                            || entropyReport.isFailedRunsTest()
                            || entropyReport.isFailedLongestRunTest()
                            || entropyReport.isFailedMonoBitTest());
        }
    }
}
