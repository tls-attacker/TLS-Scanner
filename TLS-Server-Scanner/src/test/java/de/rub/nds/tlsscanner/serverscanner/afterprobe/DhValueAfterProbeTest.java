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

import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DhValueAfterProbeTest {

    private ServerReport report;
    private DhValueAfterProbe probe;
    private ExtractedValueContainer<DhPublicKey> publicKeyContainer;

    @BeforeEach
    public void setup() {
        report = new ServerReport();
        probe = new DhValueAfterProbe();
        publicKeyContainer = new ExtractedValueContainer<>(TrackableValueType.DHE_PUBLICKEY);
    }

    @Test
    public void testSecureDhParameter() {
        BigInteger generator = new BigInteger("2");
        BigInteger publicKey = new BigInteger("65537");
        BigInteger modulus =
                new BigInteger(
                        "00e8cc972fc56fe640588194e455522facbe4b09d88f5070e"
                                + "88f4b9b12acc85ee3d354f6fa85b81e46b557b0e0d75f71"
                                + "43b266a6346962fba3184bd30ca3a94bebb4b23ae269325"
                                + "dc15ac34b7bf38aa3dde5c6b2d9fe857237d3a7e5c7e9be"
                                + "938b187cd9781de993970e73a3fbf79a049a6d804a487de"
                                + "1013f71167cbf78aa65f3",
                        16);

        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        report.putExtractedValueContainer(TrackableValueType.DHE_PUBLICKEY, publicKeyContainer);
        probe.analyze(report);

        assertEquals(
                TestResults.TRUE, report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI));
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI));
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES));
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }

    @Test
    public void testInsecureDhParameter() {
        BigInteger generator = new BigInteger("2");
        BigInteger publicKey = new BigInteger("12");
        BigInteger modulus = new BigInteger("18");

        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        report.putExtractedValueContainer(TrackableValueType.DHE_PUBLICKEY, publicKeyContainer);
        probe.analyze(report);

        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI));
        assertEquals(
                TestResults.FALSE,
                report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI));
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES));
        assertEquals(
                TestResults.COULD_NOT_TEST,
                report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }

    @Test
    public void testSecureReusedDhPublicKey() {
        BigInteger generator = new BigInteger("2");
        BigInteger publicKey = new BigInteger("65537");
        BigInteger modulus =
                new BigInteger(
                        "00e8a678364bb6f7d85d4b29ecfedab6d6caa88eb90c4ca1"
                                + "5a43a3542cdd5c39ef42bbde1b4b9b5715ae14bdedd78d"
                                + "6b5262f5ac9c2fdec09a612ef3aea969ce1327a6b5c9f3"
                                + "ac052faafebbabc9c9679bd14e0a26114ff032c95d2ed7"
                                + "3ed60cd64f497094bd4cb5839f9d7ad58fd4ccac343db5"
                                + "81c4bf8032259bc1a3d7ee4d03",
                        16);

        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        publicKeyContainer.put(new DhPublicKey(publicKey, generator, modulus));
        report.putExtractedValueContainer(TrackableValueType.DHE_PUBLICKEY, publicKeyContainer);
        probe.analyze(report);

        assertEquals(
                TestResults.TRUE, report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI));
        assertEquals(
                TestResults.TRUE,
                report.getResult(TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI));
        assertEquals(
                TestResults.FALSE, report.getResult(TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES));
        assertEquals(TestResults.TRUE, report.getResult(TlsAnalyzedProperty.REUSES_DH_PUBLICKEY));
    }
}
