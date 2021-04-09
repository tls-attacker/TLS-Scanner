/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.directraccoon;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendRaccoonCkeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import java.math.BigInteger;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonWorkflowGenerator {

    public static WorkflowTrace generateWorkflow(Config tlsConfig, DirectRaccoonWorkflowType type,
        BigInteger initialDhSecret, boolean withNullByte) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        trace.addTlsAction(new SendRaccoonCkeAction(withNullByte, initialDhSecret));
        if (null != type) {
            switch (type) {
                case CKE:
                    break;
                case CKE_CCS:
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig)));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }

    private DirectRaccoonWorkflowGenerator() {

    }

}
