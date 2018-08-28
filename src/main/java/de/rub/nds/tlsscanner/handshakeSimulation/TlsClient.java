/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.handshakeSimulation;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import java.util.List;

public class TlsClient {
    
    private final TlsClientConfig clientConfig;
    private final String hostname;
    private final int port;

    public TlsClient(TlsClientConfig clientConfig, String hostname, int port) {
        this.clientConfig = clientConfig;
        this.hostname = hostname;
        this.port = port;
    }
    
    public void run() {
        //Get relevant information from config
        ClientHelloMessage msgConfig = (ClientHelloMessage) WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CLIENT_HELLO, clientConfig.getTrace());
        Config config = clientConfig.getConfig();
        
        //Configure Client
        config.setDefaulRunningMode(RunningModeType.CLIENT);
        config.getDefaultClientConnection().setHostname(hostname);
        config.getDefaultClientConnection().setPort(port);
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage msg = new ClientHelloMessage(config);

        //Set right ProtocolVersion
        msg.setProtocolVersion(Modifiable.explicit(msgConfig.getProtocolVersion().getOriginalValue()));
        
        //Set explicit KeyShare Bytes because we do not have the private key
        List<ExtensionMessage> extensions = msgConfig.getExtensions();
        for (ExtensionMessage extension : extensions) {
            if (extension instanceof KeyShareExtensionMessage) {
                extension.setExtensionBytes(Modifiable.explicit(extension.getExtensionBytes().getOriginalValue()));
            }
        }
        
        //Set right Extensions
        msg.setExtensions(extensions);

        //Build WorkflowExecutor
        trace.addTlsAction(new SendAction(msg));
        State stateTest = new State(config, trace);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(stateTest);
        
        //Start Client
        executor.executeWorkflow();
    }
}
