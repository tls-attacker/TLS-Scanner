/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.math.BigInteger;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DhValueAfterProbeTest {

    private final CustomDhPublicKey PUBLIC_KEY_1 =
            new CustomDhPublicKey(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE);
    private final CustomDhPublicKey PUBLIC_KEY_2 =
            new CustomDhPublicKey(BigInteger.TWO, BigInteger.TWO, BigInteger.TWO);

    private ClientReport report;
    private DhValueAfterProbe probe;
    private ExtractedValueContainer<CustomDhPublicKey> publicKeyContainer;

    @BeforeEach
    public void setup() {
        report = new ClientReport();
        probe = new DhValueAfterProbe();
        publicKeyContainer = new ExtractedValueContainer<>(TrackableValueType.DHE_PUBLICKEY);
        report.setExtractedValueContainerMap(
                Collections.singletonMap(TrackableValueType.DHE_PUBLICKEY, publicKeyContainer));
    }

    @Test
    public void testSingleKey() {
        publicKeyContainer.put(PUBLIC_KEY_1);
        probe.analyze(report);
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }

    @Test
    public void testMultipleDifferentKeys() {
        publicKeyContainer.put(PUBLIC_KEY_1);
        publicKeyContainer.put(PUBLIC_KEY_2);
        probe.analyze(report);
        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }

    @Test
    public void testReusedSingleKey() {
        publicKeyContainer.put(PUBLIC_KEY_1);
        publicKeyContainer.put(PUBLIC_KEY_1);
        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }

    @Test
    public void testReusedMultipleKeys() {
        publicKeyContainer.put(PUBLIC_KEY_1);
        publicKeyContainer.put(PUBLIC_KEY_2);
        publicKeyContainer.put(PUBLIC_KEY_1);
        publicKeyContainer.put(PUBLIC_KEY_2);
        probe.analyze(report);
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }
}
