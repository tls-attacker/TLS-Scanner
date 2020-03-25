/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import java.util.Arrays;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EvaluateRandomnessAfterProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private final static byte[] HELLO_RETRY_REQUEST_CONST = ArrayConverter
            .hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    @Override
    public void analyze(SiteReport report) {
        ExtractedValueContainer container = report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        ExtractedValueContainer tempContainter = new ExtractedValueContainer(TrackableValueType.RANDOM);
        for (Object o : container.getExtractedValueList()) {
            ComparableByteArray random = (ComparableByteArray) o;
            if (!Arrays.equals(HELLO_RETRY_REQUEST_CONST, random.getArray())) {
                tempContainter.put(o);
            }
        }
        RandomEvaluationResult result = RandomEvaluationResult.NOT_ANALYZED;
        if (!tempContainter.areAllValuesDiffernt()) {
            result = RandomEvaluationResult.DUPLICATES;
        } else {
            result = RandomEvaluationResult.NO_DUPLICATES;
        }
        report.setRandomEvaluationResult(result);
    }

}
