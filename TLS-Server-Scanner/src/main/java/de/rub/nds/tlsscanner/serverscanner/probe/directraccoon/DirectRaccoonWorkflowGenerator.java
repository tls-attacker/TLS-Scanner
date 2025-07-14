/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.directraccoon;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendRaccoonCkeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;

public class DirectRaccoonWorkflowGenerator {

    /**
     * Generates a workflow trace for Direct Raccoon attack testing.
     *
     * @param tlsConfig The TLS configuration to use
     * @param type The type of workflow to generate
     * @param initialDhSecret The initial Diffie-Hellman secret
     * @param withNullByte Whether to include a null byte in the pre-master secret
     * @return The generated workflow trace
     */
    public static WorkflowTrace generateWorkflow(
            Config tlsConfig,
            DirectRaccoonWorkflowType type,
            BigInteger initialDhSecret,
            boolean withNullByte) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendRaccoonCkeAction(withNullByte, initialDhSecret));
        if (null != type) {
            switch (type) {
                case CKE:
                    break;
                case CKE_CCS:
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(
                            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
