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

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.junit.Before;
import org.junit.Test;

/*
 * Testset should check if 
 * DhValueAfterProbe detects
 * insecure DH-Parameters as 
 * insecure ones and secure 
 * parameters as secure ones
 * 
 * Shortyl: Checks If it
 * correctly identifies the
 * DH-Params
 */

public class DhValueAfterProbeTest {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    private SiteReport report;
    private HashMap<TrackableValueType, ExtractedValueContainer> cipherMap;
    private ExtractedValueContainer<BigInteger> PubKeyContainer, ModulusContainer;
    private DhValueAfterProbe test;

    //intitilizes attributes
    @Before
    public void setup() {
        this.report = new SiteReport("sample", new LinkedList<>());
        this.cipherMap = new HashMap<>();
        this.PubKeyContainer = new ExtractedValueContainer<BigInteger>(TrackableValueType.DH_PUBKEY);
        this.ModulusContainer = new ExtractedValueContainer<BigInteger>(TrackableValueType.DH_MODULUS);
        this.test = new DhValueAfterProbe();

    }

    /*
     * test if the class DhValueAfterProbe recognizes a secure public key
     */

    @Test
    public void secure_dh_param_test() {

        BigInteger secure_pubKey, secure_mod;
        secure_pubKey = new BigInteger("65537");
        // use openssl command to gen secure prime numbers: openssl dhparam
        // -text -noout 1024
        secure_mod = new BigInteger("00e8cc972fc56fe640588194e455522facbe4b09d88f5070e88f4b9b"
                + "12acc85ee3d354f6fa85b81e46b557b0e0d75f7143b266a6346962fba3184bd30ca3a94bebb4b"
                + "23ae269325dc15ac34b7bf38aa3dde5c6b2d9fe857237d3a7e5c7e9be938b187cd9781de99397"
                + "0e73a3fbf79a049a6d804a487de1013f71167cbf78aa65f3", 16);

        // store pubKey into list
        this.PubKeyContainer.put(secure_pubKey);
        this.ModulusContainer.put(secure_mod);

        this.analyse_dh_params();

        // needs get-parameter from DhVAlueAfterPr
        assert (test.getOnlyPrime() == TestResult.TRUE);
        assert (test.getOnlySafePrime() == TestResult.TRUE);
        assert (test.getUsesCommonDhPrimes() == TestResult.FALSE);
        assert (test.getReuse() == TestResult.COULD_NOT_TEST);

    }

    /*
     * Tests an insecure Key
     */

    @Test
    public void insecure_dh_param_test() {
        // BigInteger dh_pub_insecure_key, dh_insecure_mod;

        // examples for insecure values
        BigInteger insecure_key = new BigInteger("12");
        BigInteger insecure_mod = new BigInteger("18");

        this.PubKeyContainer.put(insecure_key);
        this.ModulusContainer.put(insecure_mod);

        this.analyse_dh_params();

        assert (test.getOnlyPrime() == TestResult.FALSE);
        assert (test.getOnlySafePrime() == TestResult.FALSE);
        assert (test.getUsesCommonDhPrimes() == TestResult.FALSE);
        assert (test.getReuse() == TestResult.COULD_NOT_TEST);

    }

    /*
     * Test if class detects reused public key
     */

    @Test
    public void secure_but_reused_dh_pubKey_test() {
        BigInteger secure_key, secure_mod;

        // examples for insecure values
        secure_key = new BigInteger("65537");
        secure_mod = new BigInteger("00e8a678364bb6f7d85d4b29ecfedab6d6caa88eb90c4ca15a"
                + "43a3542cdd5c39ef42bbde1b4b9b5715ae14bdedd78d6b5262f5ac9c2fdec09a612ef3a"
                + "ea969ce1327a6b5c9f3ac052faafebbabc9c9679bd14e0a26114ff032c95d2ed73ed60c"
                + "d64f497094bd4cb5839f9d7ad58fd4ccac343db581c4bf8032259bc1a3d7ee4d03", 16);

        // reuse pubKey
        this.PubKeyContainer.put(secure_key);
        this.PubKeyContainer.put(secure_key);
        this.PubKeyContainer.put(secure_key);
        this.ModulusContainer.put(secure_mod);

        this.analyse_dh_params();

        assert (test.getOnlyPrime() == TestResult.TRUE);
        assert (test.getOnlySafePrime() == TestResult.TRUE);
        assert (test.getUsesCommonDhPrimes() == TestResult.FALSE);
        assert (test.getReuse() == TestResult.TRUE);

    }

    /*
     * Executes the analysis: determies how secure the Diffie-Hellmann
     * parameters are
     */

    public void analyse_dh_params() {

        this.cipherMap.put(TrackableValueType.DH_PUBKEY, this.PubKeyContainer);
        this.cipherMap.put(TrackableValueType.DH_MODULUS, this.ModulusContainer);

        this.report.setExtractedValueContainerList(this.cipherMap);
        this.test.analyze(this.report);

    }

    // used for debugging
    public void show_testResults() {
        System.out.println("===============================");
        System.out.print("OnlyPrime:");
        System.out.println(test.getOnlyPrime());

        System.out.print("onlySafePrime:");
        System.out.println(test.getOnlySafePrime());

        System.out.print("usesCommonDhPrimes:");
        System.out.println(test.getUsesCommonDhPrimes());

        System.out.print("reuse:");
        System.out.println(test.getReuse());
        System.out.println("===============================");
    }

}
