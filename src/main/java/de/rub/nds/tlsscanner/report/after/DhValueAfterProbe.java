/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhLoader;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DhValueAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        ExtractedValueContainer publicKeyContainer = report.getExtractedValueContainerMap().get(TrackableValueType.DH_PUBKEY);
        ExtractedValueContainer modulusContainer = report.getExtractedValueContainerMap().get(TrackableValueType.DH_MODULUS);
        List<CommonDhValues> loadedCommonDhValues = CommonDhLoader.loadCommonDhValues();
        Set<CommonDhValues> usedCommonValues = new HashSet<>();
        TestResult onlyPrime = TestResult.TRUE;
        TestResult onlySafePrime = TestResult.TRUE;
        TestResult usesCommonDhPrimes = TestResult.NOT_TESTED_YET;
        TestResult reuse;

        Integer shortestBitLength = Integer.MAX_VALUE;
        if (publicKeyContainer != null && publicKeyContainer.getExtractedValueList().size() > 2) {
            if (!publicKeyContainer.areAllValuesDiffernt()) {
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

        if (modulusContainer != null && !modulusContainer.getExtractedValueList().isEmpty()) {
            for (Object o : modulusContainer.getExtractedValueList()) {
                if (onlyPrime == TestResult.TRUE && !((BigInteger) o).isProbablePrime(30)) {
                    onlyPrime = TestResult.FALSE;
                }
                if (onlySafePrime == TestResult.TRUE && !isSafePrime((BigInteger) o)) {
                    onlySafePrime = TestResult.FALSE;
                }

                for (CommonDhValues value : loadedCommonDhValues) {
                    if (value.getModulus().equals(o)) {
                        usedCommonValues.add(value);
                        break;
                    }
                }

                if (shortestBitLength > ((BigInteger) o).bitLength()) {
                    shortestBitLength = ((BigInteger) o).bitLength();
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

}
