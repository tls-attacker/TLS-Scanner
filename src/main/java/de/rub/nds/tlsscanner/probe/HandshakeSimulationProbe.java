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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfigIO;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
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

    public HandshakeSimulationProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HANDSHAKE_SIMULATION, config, 10);
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
        ClientHelloMessage msg = new ClientHelloMessage(config);
        List<ExtensionMessage> extensions = WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CLIENT_HELLO, clientConfig.getTrace()).getExtensions();
        for (ExtensionMessage extension : extensions) {
            if (extension.getExtensionBytes().getValue()!=null) {
                extension.setExtensionBytes(Modifiable.explicit(extension.getExtensionBytes().getValue()));
            }
        }
        msg.setExtensions(extensions);
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(msg));
        trace.addTlsAction(new ReceiveAction());
        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn(ex);
        }
        simulatedClient.setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        simulatedClient.setHighestClientProtocolVersion(state.getTlsContext().getHighestClientProtocolVersion());
        if (simulatedClient.getReceivedServerHello()) {
            simulatedClient.setSelectedProtocolVersion(state.getTlsContext().getSelectedProtocolVersion());
            simulatedClient.setSelectedCiphersuite(state.getTlsContext().getSelectedCipherSuite());
            if (simulatedClient.getSelectedCiphersuite().toString().contains("_DHE_") || simulatedClient.getSelectedCiphersuite().toString().contains("_ECDHE_")) {
                simulatedClient.setForwardSecrecy(true);
            } else {
                simulatedClient.setForwardSecrecy(false);
            }
            simulatedClient.setSelectedCompressionMethod(state.getTlsContext().getSelectedCompressionMethod());
            simulatedClient.setNegotiatedExtensionSet(state.getTlsContext().getNegotiatedExtensionSet());
        }
        simulatedClient.setReceivedCertificate(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace));
        if (simulatedClient.getReceivedCertificate()) {
            //Do something
        }
        simulatedClient.setReceivedServerKeyExchange(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace));
        if (simulatedClient.getReceivedServerKeyExchange()) {
            if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA") && state.getTlsContext().getServerRSAPublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerRSAPublicKey().bitLength()));
            } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_DH") && state.getTlsContext().getServerDhPublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerDhPublicKey().bitLength()));
            } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_PSK") && state.getTlsContext().getServerPSKPublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerPSKPublicKey().bitLength()));
            } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_SRP") && state.getTlsContext().getServerSRPPublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerSRPPublicKey().bitLength()));
            } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_ECDH") && state.getTlsContext().getServerEcPublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerEcPublicKey().getByteX().length*8));
            } else if (simulatedClient.getSelectedCiphersuite().usesGOSTR3411() && state.getTlsContext().getServerGostEc01PublicKey()!=null) {
                simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerGostEc01PublicKey().getByteX().length*8));
            }
            simulatedClient.setSelectedNamedGroup(state.getTlsContext().getSelectedGroup().name());
        }
        if (simulatedClient.getServerPublicKeyLength()==null && state.getTlsContext().getServerRsaModulus()!=null) {
            simulatedClient.setServerPublicKeyLength(Integer.toString(state.getTlsContext().getServerRsaModulus().bitLength()));
        }
        simulatedClient.setReceivedCertificateRequest(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, trace));
        simulatedClient.setReceivedServerHelloDone(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace));
        this.simulatedClientList.add(simulatedClient);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return report.getVersions()!=null;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
    
}
