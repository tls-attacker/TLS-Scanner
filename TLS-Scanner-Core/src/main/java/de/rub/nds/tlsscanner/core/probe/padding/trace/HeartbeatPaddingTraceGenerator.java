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
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.probe.padding.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsscanner.core.probe.padding.vector.PaddingVector;
import java.util.LinkedList;

public class HeartbeatPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     * Constructs a new HeartbeatPaddingTraceGenerator with the specified record generator type.
     *
     * @param recordGeneratorType The type of padding record generator to use for creating padding
     *     vectors
     */
    public HeartbeatPaddingTraceGenerator(PaddingRecordGeneratorType recordGeneratorType) {
        super(recordGeneratorType);
    }

    /**
     * Creates a workflow trace for testing padding oracle vulnerabilities using heartbeat messages.
     * The trace includes a handshake, an application message with the padding vector, and a
     * heartbeat message.
     *
     * @param config The TLS configuration to use for the workflow
     * @param vector The padding vector to apply to the application message record
     * @return A workflow trace configured for padding oracle testing with heartbeat messages
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
        HeartbeatMessage heartbeat = new HeartbeatMessage();
        SendAction sendAction = new SendAction(applicationMessage, heartbeat);
        sendAction.setConfiguredRecords(new LinkedList<>());
        sendAction.getConfiguredRecords().add(vector.createRecord());
        sendAction.getConfiguredRecords().add(new Record(config));
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
