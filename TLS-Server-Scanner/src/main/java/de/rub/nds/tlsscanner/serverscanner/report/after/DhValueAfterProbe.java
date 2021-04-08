/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.after.prime.CommonDhLoader;
import de.rub.nds.tlsscanner.serverscanner.report.after.prime.CommonDhValues;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DhValueAfterProbe extends AfterProbe {

    private TestResult onlyPrime;
    private TestResult onlySafePrime;
    private TestResult usesCommonDhPrimes;
    private TestResult reuse;

    @Override
    public void analyze(SiteReport report) {
        ExtractedValueContainer publicKeyContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.DHE_PUBLICKEY);

        List<CommonDhValues> loadedCommonDhValues = CommonDhLoader.loadCommonDhValues();
        Set<CommonDhValues> usedCommonValues = new HashSet<>();
        onlyPrime = TestResult.TRUE;
        onlySafePrime = TestResult.TRUE;
        usesCommonDhPrimes = TestResult.NOT_TESTED_YET;

        Integer shortestBitLength = Integer.MAX_VALUE;
        if (publicKeyContainer != null && publicKeyContainer.getExtractedValueList().size() > 2) {
            if (!publicKeyContainer.areAllValuesDifferent()) {
                reuse = TestResult.TRUE;
            } else {
                reuse = TestResult.FALSE;
            }
        } else {
            if (report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
                reuse = TestResult.ERROR_DURING_TEST;
            } else {
                reuse = TestResult.COULD_NOT_TEST;
            }
        }

        if (publicKeyContainer != null && !publicKeyContainer.getExtractedValueList().isEmpty()) {
            for (Object o : publicKeyContainer.getExtractedValueList()) {
                CustomDhPublicKey publicKey = (CustomDhPublicKey) o;
                if (onlyPrime == TestResult.TRUE && !publicKey.getModulus().isProbablePrime(30)) {
                    onlyPrime = TestResult.FALSE;
                }
                if (onlySafePrime == TestResult.TRUE && !isSafePrime(publicKey.getModulus())) {
                    onlySafePrime = TestResult.FALSE;
                }

                for (CommonDhValues value : loadedCommonDhValues) {
                    if (value.getModulus().equals(publicKey.getModulus())) {
                        usedCommonValues.add(value);
                        break;
                    }
                }

                if (shortestBitLength > ((BigInteger) publicKey.getModulus()).bitLength()) {
                    shortestBitLength = ((BigInteger) publicKey.getModulus()).bitLength();
                }
            }
            if (usedCommonValues.size() > 0) {
                report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.TRUE);
            } else {
                report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.FALSE);
            }
            if (usedCommonValues.size() > 0) {
                usesCommonDhPrimes = TestResult.TRUE;
            } else {
                usesCommonDhPrimes = TestResult.FALSE;
            }
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.COULD_NOT_TEST);
            onlyPrime = TestResult.COULD_NOT_TEST;
            onlySafePrime = TestResult.COULD_NOT_TEST;
            usesCommonDhPrimes = TestResult.COULD_NOT_TEST;
        }

        report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, usesCommonDhPrimes);
        report.putResult(AnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI, onlyPrime);
        report.putResult(AnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI, onlySafePrime);
        report.setUsedCommonDhValueList(usedCommonValues);
        report.putResult(AnalyzedProperty.REUSES_DH_PUBLICKEY, reuse);
        if (shortestBitLength != Integer.MAX_VALUE) {
            report.setWeakestDhStrength(shortestBitLength);
        }
    }

    private boolean isSafePrime(BigInteger bigInteger) {
        return bigInteger.shiftRight(1).isProbablePrime(30);
    }

    public TestResult getOnlyPrime() {
        return this.onlyPrime;
    }

    public TestResult getOnlySafePrime() {
        return this.onlySafePrime;
    }

    public TestResult getUsesCommonDhPrimes() {
        return this.usesCommonDhPrimes;
    }

    public TestResult getReuse() {
        return this.reuse;
    }

}
