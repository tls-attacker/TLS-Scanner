/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.trace;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.vector.LongPaddingGenerator;
import de.rub.nds.tlsscanner.core.probe.padding.vector.LongRecordPaddingGenerator;
import de.rub.nds.tlsscanner.core.probe.padding.vector.MediumPaddingGenerator;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVectorGenerator;
import de.rub.nds.tlsscanner.core.probe.padding.vector.ShortPaddingGenerator;
import de.rub.nds.tlsscanner.core.probe.padding.vector.VeryShortPaddingGenerator;

public abstract class PaddingTraceGenerator {

    protected final PaddingVectorGenerator vectorGenerator;

    /**
     * Returns the padding vector generator used by this trace generator.
     *
     * @return The padding vector generator instance
     */
    public PaddingVectorGenerator getVectorGenerator() {
        return vectorGenerator;
    }

    /**
     * Constructs a PaddingTraceGenerator with the specified record generator type. Initializes the
     * appropriate padding vector generator based on the type.
     *
     * @param type The type of padding record generator to use
     * @throws IllegalArgumentException if the record generator type is unknown
     */
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

    /**
     * Creates a workflow trace for testing padding oracle vulnerabilities. Subclasses must
     * implement this method to define specific workflow patterns for different padding oracle test
     * scenarios.
     *
     * @param config The TLS configuration to use for the workflow
     * @param vector The padding vector to apply during the test
     * @return A workflow trace configured for padding oracle testing
     */
    public abstract WorkflowTrace getPaddingOracleWorkflowTrace(
            Config config, PaddingVector vector);
}
