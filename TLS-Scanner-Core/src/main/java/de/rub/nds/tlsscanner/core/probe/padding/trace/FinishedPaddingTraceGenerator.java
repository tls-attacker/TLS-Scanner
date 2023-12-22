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
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import java.util.LinkedList;

public class FinishedPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     * @param type
     */
    public FinishedPaddingTraceGenerator(PaddingRecordGeneratorType type) {
        super(type);
    }

    /**
     * @param config
     * @param vector
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        RunningModeType runningMode = config.getDefaultRunningMode();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, runningMode);
        if (runningMode == RunningModeType.CLIENT) {
            // remove receive Server CCS, FIN
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
        }
        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<Record> recordList = new LinkedList<>();
        for (ProtocolMessage msg : sendAction.getConfiguredMessages()) {
            if (msg instanceof FinishedMessage) {
                recordList.add(vector.createRecord());
            } else {
                recordList.add(new Record(config));
            }
        }
        sendAction.setConfiguredRecords(recordList);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
