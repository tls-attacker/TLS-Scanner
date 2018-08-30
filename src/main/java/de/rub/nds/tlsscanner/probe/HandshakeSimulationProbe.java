/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.handshakeSimulation.TlsClientConfigIO;
import de.rub.nds.tlsscanner.handshakeSimulation.SimulatedClient;
import static de.rub.nds.tlsscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.HandshakeSimulationResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.io.File;
import java.util.LinkedList;
import java.util.List;

public class HandshakeSimulationProbe extends TlsProbe {
    
    private static final String RESOURCE_FOLDER = "client_configs";
    
    private final List<SimulatedClient> simulatedClientList;

    public HandshakeSimulationProbe(ScannerConfig config) {
        super(ProbeType.HANDSHAKE_SIMULATION, config, 0);
        this.simulatedClientList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        TlsClientConfigIO clientConfigIO = new TlsClientConfigIO();
        for (File configFile : clientConfigIO.getClientConfigFileList(RESOURCE_FOLDER)) {
            TlsClientConfig clientConfig = clientConfigIO.readConfigFromFile(configFile);
            SimulatedClient simulatedClient = new SimulatedClient(clientConfig.getType(), clientConfig.getVersion());
            Config config = clientConfig.getConfig();
            getScannerConfig().getClientDelegate().applyDelegate(config);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopActionsAfterFatal(true);
            config.setStopRecievingAfterFatal(true);
            runClient(clientConfig, config, simulatedClient);
        }
        return new HandshakeSimulationResult(simulatedClientList);
    }
    
    private void runClient(TlsClientConfig clientConfig, Config config, SimulatedClient simulatedClient) {
        ClientHelloMessage msgConfig = (ClientHelloMessage) WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CLIENT_HELLO, clientConfig.getTrace());
        List<ExtensionMessage> extensions = msgConfig.getExtensions();
        for (ExtensionMessage extension : extensions) {
            if (extension instanceof KeyShareExtensionMessage) {
                extension.setExtensionBytes(Modifiable.explicit(extension.getExtensionBytes().getOriginalValue()));
            }
        }
        ClientHelloMessage msg = new ClientHelloMessage(config);
        msg.setProtocolVersion(Modifiable.explicit(msgConfig.getProtocolVersion().getOriginalValue()));
        msg.setExtensions(extensions);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(msg));
        trace.addTlsAction(new GenericReceiveAction());
        trace.addTlsAction(new GenericReceiveAction());
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn(ex);
        }
        simulatedClient.setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        if (simulatedClient.isReceivedServerHello()) {
            simulatedClient.setSelectedProtocolVersion(state.getTlsContext().getSelectedProtocolVersion());
            simulatedClient.setSelectedCiphersuite(state.getTlsContext().getSelectedCipherSuite());
            simulatedClient.setSelectedCompressionMethod(state.getTlsContext().getSelectedCompressionMethod());
            simulatedClient.setSelectedNamedGroup(state.getTlsContext().getSelectedGroup());
        }
        this.simulatedClientList.add(simulatedClient);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
    
}
