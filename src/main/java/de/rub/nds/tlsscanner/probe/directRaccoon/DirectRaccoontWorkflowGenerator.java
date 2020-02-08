/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.directRaccoon;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoontWorkflowGenerator {

    /**
     *
     * @param tlsConfig
     * @return
     */
    public static WorkflowTrace generateWorkflowFirstStep (Config tlsConfig) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createTlsEntryWorkflowtrace(tlsConfig.getDefaultClientConnection());
        //WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(tlsConfig)));
        return trace;
    } 
    
    /**
     *
     * @param tlsConfig
     * @param type
     * @param clientPublicKey
     * @return
     */
    public static WorkflowTrace generateWorkflowSecondStep(Config tlsConfig, DirectRaccoonWorkflowType type, byte[] clientPublicKey) {
        WorkflowTrace trace = new WorkflowTrace();
        DHClientKeyExchangeMessage cke = new DHClientKeyExchangeMessage(tlsConfig);
        cke.setPublicKey(Modifiable.explicit(clientPublicKey));
        if (null != type) {
            switch (type) {
                case CKE:
                    trace.addTlsAction(new SendAction(cke));
                    break;
                case CKE_CCS:
                    trace.addTlsAction(new SendAction(cke, new ChangeCipherSpecMessage(tlsConfig)));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(new SendAction(cke, new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(
                            tlsConfig)));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }

    private DirectRaccoontWorkflowGenerator() {

    }
    
}
