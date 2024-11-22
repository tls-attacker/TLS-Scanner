/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.passive;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import java.util.List;

public class CbcIvExtractor extends StatExtractor<State, ComparableByteArray> {

    public CbcIvExtractor() {
        super(TrackableValueType.CBC_IV);
    }

    @Override
    public void extract(State state) {
        if (state.getTlsContext().getSelectedCipherSuite() != null
                && state.getTlsContext().getSelectedCipherSuite().isCBC()) {
            WorkflowTrace trace = state.getWorkflowTrace();
            List<Record> allReceivedRecords = WorkflowTraceResultUtil.getAllReceivedRecords(trace);
            for (Record receivedRecord : allReceivedRecords) {
                if (receivedRecord instanceof Record) {
                    if (((Record) receivedRecord).getComputations() != null) {
                        ModifiableByteArray cbcInitialisationVector =
                                ((Record) receivedRecord)
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
