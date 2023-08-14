/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.trace;

import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingVectorGeneratorType;

public class PaddingTraceGeneratorFactory {

    private PaddingTraceGeneratorFactory() {}

    public static PaddingTraceGenerator getPaddingTraceGenerator(
            PaddingVectorGeneratorType vectorGeneratorType,
            PaddingRecordGeneratorType recordGeneratorType) {
        switch (vectorGeneratorType) {
            case CLASSIC:
                return new ClassicPaddingTraceGenerator(recordGeneratorType);
            case FINISHED:
                return new FinishedPaddingTraceGenerator(recordGeneratorType);
            case FINISHED_RESUMPTION:
                return new FinishedResumptionPaddingTraceGenerator(recordGeneratorType);
            case CLOSE_NOTIFY:
                return new ClassicCloseNotifyTraceGenerator(recordGeneratorType);
            case CLASSIC_DYNAMIC:
                return new ClassicDynamicPaddingTraceGenerator(recordGeneratorType);
            case HEARTBEAT:
                return new HeartbeatPaddingTraceGenerator(recordGeneratorType);
            default:
                throw new IllegalArgumentException(
                        "Unknown PaddingTraceGenerator: " + vectorGeneratorType);
        }
    }
}
