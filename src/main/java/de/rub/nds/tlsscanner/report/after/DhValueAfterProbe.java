package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhLoader;
import de.rub.nds.tlsscanner.report.after.prime.CommonDhValues;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class DhValueAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        List<ExtractedValueContainer> extractedValueContainerList = report.getExtractedValueContainerList();
        List<CommonDhValues> loadedCommonDhValues = CommonDhLoader.loadCommonDhValues();
        List<CommonDhValues> usedCommonValues = new LinkedList<>();
        Boolean onlyPrime = true;
        Boolean onlySafePrime = true;
        Boolean reuse = false;
        for (ExtractedValueContainer container : extractedValueContainerList) {
            if (container.getType() == TrackableValueType.DH_PUBKEY) {
                if (!container.areAllValuesDiffernt()) {
                    reuse = true;
                    break;
                }
            }
            if (container.getType() == TrackableValueType.DH_MODULUS) {
                for (Object o : container.getExtractedValueList()) {
                    if (onlyPrime && !((BigInteger) o).isProbablePrime(30)) {
                        onlyPrime = false;
                    }
                    if (onlySafePrime && !isSafePrime((BigInteger) o)) {
                        onlySafePrime = false;
                    }

                    for (CommonDhValues value : loadedCommonDhValues) {
                        if (value.getModulus().equals(o)) {
                            usedCommonValues.add(value);
                            break;
                        }
                    }
                }
            }
        }
        if (usedCommonValues.size() > 0) {
            report.setUsesCommonDhPrimes(true);
        } else {
            report.setUsesCommonDhPrimes(false);
        }
        report.setUsesNonPrimeModuli(!onlyPrime);
        report.setUsesNonSafePrimeModuli(!onlySafePrime);
        report.setUsedCommonDhValueList(usedCommonValues);
        report.setDhPubkeyReuse(reuse);

    }

    private boolean isSafePrime(BigInteger bigInteger) {
        return bigInteger.shiftRight(1).isProbablePrime(30);
    }

}
