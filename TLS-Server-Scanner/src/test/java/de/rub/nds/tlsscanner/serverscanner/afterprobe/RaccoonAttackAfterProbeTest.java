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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RaccoonAttackAfterProbeTest {

    private ServerReport report;
    private RaccoonAttackAfterProbe probe;
    private ExtractedValueContainer<DhPublicKey> publicKeyContainer;

    @BeforeEach
    public void setup() {
        report = new ServerReport();
        probe = new RaccoonAttackAfterProbe();
        publicKeyContainer = new ExtractedValueContainer<>(TrackableValueType.DHE_PUBLICKEY);
        report.putExtractedValueContainer(TrackableValueType.DHE_PUBLICKEY, publicKeyContainer);
    }

    @Test
    public void testDoesNotReuseKey() {
        report.putResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY, TestResults.FALSE);
        probe.analyze(report);
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK));
    }

    @Test
    public void testReusesKey() {
        report.putResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY, TestResults.TRUE);
        probe.analyze(report);
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK));
    }

    @Test
    public void testSha256PrfProbability() {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF, TestResults.TRUE);
        BigInteger generator = new BigInteger("2");
        BigInteger publicKey = new BigInteger("65537");
        BigInteger modulus =
                new BigInteger(
                        "00e8cc972fc56fe640588194e455522facbe4b09d88f5070"
                                + "e88f4b9b12acc85ee3d354f6fa85b81e46b557b0e0d75"
                                + "f7143b266a6346962fba3184bd30ca3a94bebb4b23ae2"
                                + "69325dc15ac34b7bf38aa3dde5c6b2d9fe857237d3a7e"
                                + "5c7e9be938b187cd9781de993970e73a3fbf79a049a6d"
                                + "804a487de1013f71167cbf78aa65f3",
                        16);
        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        probe.analyze(report);

        // (modulus length + hash length + maximum padding) % blocksize
        int expectedBitsLeaked = (modulus.bitLength() + 64 + (512 - 8)) % 512;
        // the probability is approximately 1/2^bitsLeaked, but calculation may differ by a factor
        // of up to 2 because of rounding
        BigDecimal expectedChance =
                BigDecimal.ONE.divide(
                        BigDecimal.valueOf(2).pow(expectedBitsLeaked), 128, RoundingMode.HALF_DOWN);
        BigDecimal lowerBound = expectedChance.divide(BigDecimal.valueOf(2), RoundingMode.FLOOR);
        BigDecimal upperBound = expectedChance.multiply(BigDecimal.valueOf(2));
        BigDecimal probability =
                report.getRaccoonAttackProbabilities().get(0).getChanceForEquation();
        assertTrue(lowerBound.compareTo(probability) < 0);
        assertTrue(upperBound.compareTo(probability) > 0);
    }
}
