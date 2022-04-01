/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.padding.tarce;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.LongPaddingGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.LongRecordPaddingGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.MediumPaddingGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.PaddingVector;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.PaddingVectorGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.ShortPaddingGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.padding.vector.VeryShortPaddingGenerator;

public abstract class PaddingTraceGenerator {

    protected final PaddingVectorGenerator vectorGenerator;

    public PaddingVectorGenerator getVectorGenerator() {
        return vectorGenerator;
    }

    public PaddingTraceGenerator(PaddingRecordGeneratorType type) {
        switch (type) {
            case LONG_RECORD:
                vectorGenerator = new LongRecordPaddingGenerator();
                break;
            case LONG:
                vectorGenerator = new LongPaddingGenerator();
                break;
            case MEDIUM:
                vectorGenerator = new MediumPaddingGenerator();
                break;
            case SHORT:
                vectorGenerator = new ShortPaddingGenerator();
                break;
            case VERY_SHORT:
                vectorGenerator = new VeryShortPaddingGenerator();
                break;
            default:
                throw new IllegalArgumentException("Unknown RecordGenerator Type");
        }

    }

    public abstract WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector);
}
