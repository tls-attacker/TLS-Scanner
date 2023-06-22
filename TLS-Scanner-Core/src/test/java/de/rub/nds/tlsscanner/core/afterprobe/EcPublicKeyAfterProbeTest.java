/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.math.BigInteger;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EcPublicKeyAfterProbeTest {

    private final CustomEcPublicKey ECDH_X25519_PUBLIC_KEY =
            new CustomEcPublicKey(BigInteger.ONE, BigInteger.TWO, NamedGroup.ECDH_X25519);
    private final CustomEcPublicKey ECDH_X448_PUBLIC_KEY =
            new CustomEcPublicKey(BigInteger.TWO, BigInteger.ONE, NamedGroup.ECDH_X448);

    private TlsCoreTestReport report;
    private EcPublicKeyAfterProbe<TlsCoreTestReport> probe;
    private ExtractedValueContainer<CustomEcPublicKey> publicKeyContainer;

    @BeforeEach
    public void setup() {
        report = new TlsCoreTestReport();
        probe = new EcPublicKeyAfterProbe<>();
        publicKeyContainer = new ExtractedValueContainer<>(TrackableValueType.ECDHE_PUBKEY);
    }

    @Test
    public void testSingleKey() {
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        report.setExtractedValueContainerMap(
                Collections.singletonMap(TrackableValueType.ECDHE_PUBKEY, publicKeyContainer));
        probe.analyze(report);

        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY));
    }

    @Test
    public void testMultipleDifferentKeys() {
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        publicKeyContainer.put(ECDH_X448_PUBLIC_KEY);
        report.setExtractedValueContainerMap(
                Collections.singletonMap(TrackableValueType.ECDHE_PUBKEY, publicKeyContainer));
        probe.analyze(report);

        assertEquals(TestResults.FALSE, report.getResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY));
    }

    @Test
    public void testReusedSingleKey() {
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        report.setExtractedValueContainerMap(
                Collections.singletonMap(TrackableValueType.ECDHE_PUBKEY, publicKeyContainer));
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY));
    }

    @Test
    public void testReusedMultipleKeys() {
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        publicKeyContainer.put(ECDH_X448_PUBLIC_KEY);
        publicKeyContainer.put(ECDH_X25519_PUBLIC_KEY);
        publicKeyContainer.put(ECDH_X448_PUBLIC_KEY);
        report.setExtractedValueContainerMap(
                Collections.singletonMap(TrackableValueType.ECDHE_PUBKEY, publicKeyContainer));
        probe.analyze(report);

        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.REUSES_EC_PUBLICKEY));
    }
}
