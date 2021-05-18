/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EvaluateRandomnessAfterProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte[] HELLO_RETRY_REQUEST_CONST =
        ArrayConverter.hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    @Override
    public void analyze(SiteReport report) {

        if (report.getExtractedValueContainerMap().isEmpty()) {
            report.setRandomEvaluationResult(RandomEvaluationResult.NO_DUPLICATES);
            return;
        }

        ExtractedValueContainer container = report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        ExtractedValueContainer tempContainer = new ExtractedValueContainer(TrackableValueType.RANDOM);
        for (Object o : container.getExtractedValueList()) {
            ComparableByteArray random = (ComparableByteArray) o;
            if (!Arrays.equals(HELLO_RETRY_REQUEST_CONST, random.getArray())) {
                tempContainer.put(o);
            }
        }
        RandomEvaluationResult result = RandomEvaluationResult.NOT_ANALYZED;
        if (!tempContainer.areAllValuesDifferent()) {
            result = RandomEvaluationResult.DUPLICATES;
        } else {
            result = RandomEvaluationResult.NO_DUPLICATES;
        }
        report.setRandomEvaluationResult(result);
    }

}
