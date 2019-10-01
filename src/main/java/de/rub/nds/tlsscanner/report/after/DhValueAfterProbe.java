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
        List<ExtractedValueContainer> extractedValueContainerList = report.getExtractedValueContainerList();
        List<CommonDhValues> loadedCommonDhValues = CommonDhLoader.loadCommonDhValues();
        Set<CommonDhValues> usedCommonValues = new HashSet<>();
        TestResult onlyPrime;
        TestResult onlySafePrime;
        TestResult reuse;
        if (extractedValueContainerList.isEmpty()) {
            onlyPrime = TestResult.COULD_NOT_TEST;
            onlySafePrime = TestResult.COULD_NOT_TEST;
            reuse = TestResult.COULD_NOT_TEST;
        } else {
            onlyPrime = TestResult.TRUE;
            onlySafePrime = TestResult.TRUE;
            reuse = TestResult.FALSE;
        }
        int shortestBitLength = Integer.MAX_VALUE;
        for (ExtractedValueContainer container : extractedValueContainerList) {
            if (container.getType() == TrackableValueType.DH_PUBKEY) {
                if (!container.areAllValuesDiffernt()) {
                    reuse = TestResult.TRUE;
                    break;
                }
            }
            if (container.getType() == TrackableValueType.DH_MODULUS) {
                for (Object o : container.getExtractedValueList()) {
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
            }
        }
        if (extractedValueContainerList.isEmpty()) {
            report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.COULD_NOT_TEST);
        } else {
            if (usedCommonValues.size() > 0) {
                report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.TRUE);
            } else {
                report.putResult(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, TestResult.FALSE);
            }
        }
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
