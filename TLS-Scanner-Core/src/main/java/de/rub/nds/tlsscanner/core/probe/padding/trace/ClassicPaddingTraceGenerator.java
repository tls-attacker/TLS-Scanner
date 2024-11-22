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
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import java.util.LinkedList;

public class ClassicPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     * @param recordGeneratorType
     */
    public ClassicPaddingTraceGenerator(PaddingRecordGeneratorType recordGeneratorType) {
        super(recordGeneratorType);
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
        if (runningMode == RunningModeType.SERVER) {
            // we assume that the client sends the first application message
            trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        }
        ApplicationMessage applicationMessage = new ApplicationMessage();
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.setConfiguredRecords(new LinkedList<>());
        sendAction.getConfiguredRecords().add(vector.createRecord());
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
