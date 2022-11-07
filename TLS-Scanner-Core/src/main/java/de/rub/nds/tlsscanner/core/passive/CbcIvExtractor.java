/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.passive;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;

public class CbcIvExtractor extends StatExtractor<ComparableByteArray> {

    public CbcIvExtractor() {
        super(TrackableValueType.CBC_IV);
    }

    @Override
    public void extract(State state) {
        if (state.getTlsContext().getSelectedCipherSuite() != null
                && state.getTlsContext().getSelectedCipherSuite().isCBC()) {
            WorkflowTrace trace = state.getWorkflowTrace();
            List<AbstractRecord> allReceivedRecords =
                    WorkflowTraceUtil.getAllReceivedRecords(trace);
            for (AbstractRecord abstractRecord : allReceivedRecords) {
                if (abstractRecord instanceof Record) {
                    if (((Record) abstractRecord).getComputations() != null) {
                        ModifiableByteArray cbcInitialisationVector =
                                ((Record) abstractRecord)
                                        .getComputations()
                                        .getCbcInitialisationVector();
                        if (cbcInitialisationVector != null) {
                            put(new ComparableByteArray(cbcInitialisationVector.getValue()));
                        }
                    }
                }
            }
        }
    }
}
