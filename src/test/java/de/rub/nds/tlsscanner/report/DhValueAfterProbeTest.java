/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.DhValueAfterProbe;

import static org.junit.Assert.assertSame;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.junit.Before;
import org.junit.Test;

/*
 * Testset should check if  DhValueAfterProbe detects insecure DH-Parameters
 *  as insecure ones and secure parameters as secure ones
 *  
 *  Shortly: Checks If it correctly identifies the DH-Params
 */

public class DhValueAfterProbeTest {

    private static final Logger LOGGER = (Logger) LogManager.getLogger();

    private SiteReport report;
    private HashMap<TrackableValueType, ExtractedValueContainer> cipherMap;
    private ExtractedValueContainer<BigInteger> pubkeyContainer, modulusContainer;
    private DhValueAfterProbe test;

    // intitilizes attributes
    @Before
    public void setup() {
        report = new SiteReport("sample", new LinkedList<>());
        cipherMap = new HashMap<>();
        pubkeyContainer = new ExtractedValueContainer<BigInteger>(TrackableValueType.DH_PUBKEY);
        modulusContainer = new ExtractedValueContainer<BigInteger>(TrackableValueType.DH_MODULUS);
        test = new DhValueAfterProbe();

    }

    /*
     * test if method analyze of class DhValueAfterProbe 
     * recognizes a secure public key as such
     */
    @Test
    public void secureDhParamTestAnalyze() {

        BigInteger securePubkey, secureMod;
        securePubkey = new BigInteger("65537");
        // openssl command for dhparams: openssl dhparam -text -noout 1024
        secureMod = new BigInteger(
            "00e8cc972fc56fe640588194e455522facbe4b09d88f5070e"
            + "88f4b9b12acc85ee3d354f6fa85b81e46b557b0e0d75f71"
            + "43b266a6346962fba3184bd30ca3a94bebb4b23ae269325"
            + "dc15ac34b7bf38aa3dde5c6b2d9fe857237d3a7e5c7e9be"
            + "938b187cd9781de993970e73a3fbf79a049a6d804a487de"
            + "1013f71167cbf78aa65f3", 16);

        // store pubKey into list
        pubkeyContainer.put(securePubkey);
        modulusContainer.put(secureMod);

        analyseDhParams();

        // needs get-parameter from DhVAlueAfterPr
        assertSame(test.getOnlyPrime(), TestResult.TRUE);
        assertSame(test.getOnlySafePrime(), TestResult.TRUE);
        assertSame(test.getUsesCommonDhPrimes(), TestResult.FALSE);
        assertSame(test.getReuse(), TestResult.COULD_NOT_TEST);

    }

    /*
     * Tests if method analyze recognizes an insecure parametes as such
     */
    @Test
    public void insecureDhParamTestAnalyze() {
        // examples for insecure values
        BigInteger insecureKey = new BigInteger("12");
        BigInteger insecureMod = new BigInteger("18");

        pubkeyContainer.put(insecureKey);
        modulusContainer.put(insecureMod);

        analyseDhParams();

        assertSame(test.getOnlyPrime(), TestResult.FALSE);
        assertSame(test.getOnlySafePrime(), TestResult.FALSE);
        assertSame(test.getUsesCommonDhPrimes(), TestResult.FALSE);
        assertSame(test.getReuse(), TestResult.COULD_NOT_TEST);

    }

    /*
     * Test if method anaylize detects reused public
     * key
     */
    @Test
    public void secureReusedDhPubkeyTestAnalyze() {
        BigInteger secureKey, secureMod;

        // examples for insecure values
        secureKey = new BigInteger("65537");
        secureMod = new BigInteger(
            "00e8a678364bb6f7d85d4b29ecfedab6d6caa88eb90c4ca1"
            + "5a43a3542cdd5c39ef42bbde1b4b9b5715ae14bdedd78d" 
            + "6b5262f5ac9c2fdec09a612ef3aea969ce1327a6b5c9f3"
            + "ac052faafebbabc9c9679bd14e0a26114ff032c95d2ed7"
            + "3ed60cd64f497094bd4cb5839f9d7ad58fd4ccac343db5"
            + "81c4bf8032259bc1a3d7ee4d03", 16);

        // reuse pubKey
        pubkeyContainer.put(secureKey);
        pubkeyContainer.put(secureKey);
        pubkeyContainer.put(secureKey);
        modulusContainer.put(secureMod);

        analyseDhParams();

        assertSame(test.getOnlyPrime(), TestResult.TRUE);
        assertSame(test.getOnlySafePrime(), TestResult.TRUE);
        assertSame(test.getUsesCommonDhPrimes(), TestResult.FALSE);
        assertSame(test.getReuse(), TestResult.TRUE);

    }

    /*
     * Executes the analysis: determies how secure the Diffie-Hellmann
     * parameters are
     */
    public void analyseDhParams() {

        cipherMap.put(TrackableValueType.DH_PUBKEY, pubkeyContainer);
        cipherMap.put(TrackableValueType.DH_MODULUS, modulusContainer);

        report.setExtractedValueContainerList(cipherMap);
        test.analyze(report);

    }

}
