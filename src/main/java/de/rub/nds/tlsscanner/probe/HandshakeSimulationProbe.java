/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class HandshakeSimulationProbe extends TlsProbe {

    private static final String RESOURCE_FOLDER = "extracted_client_configs";

    private final List<SimulatedClient> simulatedClientList;

    public HandshakeSimulationProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HANDSHAKE_SIMULATION, config, 10);
        simulatedClientList = new LinkedList<>();
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
            simulateClient(clientConfig, config, simulatedClient);
        }
        return new HandshakeSimulationResult(simulatedClientList);
    }

    private void simulateClient(TlsClientConfig clientConfig, Config config, SimulatedClient simulatedClient) {
        ClientHelloMessage msg = new ClientHelloMessage(config);
        List<ExtensionMessage> extensions = WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CLIENT_HELLO, clientConfig.getTrace()).getExtensions();
        for (ExtensionMessage extension : extensions) {
            if (extension.getExtensionBytes().getValue() != null) {
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
        evaluateClient(clientConfig, state, simulatedClient);
    }

    private void evaluateClient(TlsClientConfig clientConfig, State state, SimulatedClient simulatedClient) {
        WorkflowTrace trace = state.getWorkflowTrace();
        TlsContext context = state.getTlsContext();
        try {
            simulatedClient.setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
            simulatedClient.setHighestClientProtocolVersion(context.getHighestClientProtocolVersion());
            if (simulatedClient.getReceivedServerHello()) {
                simulatedClient.setSelectedProtocolVersion(context.getSelectedProtocolVersion());
                simulatedClient.setSelectedCiphersuite(context.getSelectedCipherSuite());
                if (simulatedClient.getSelectedCiphersuite().toString().contains("_DHE_")
                        || simulatedClient.getSelectedCiphersuite().toString().contains("_ECDHE_")) {
                    simulatedClient.setForwardSecrecy(true);
                } else {
                    simulatedClient.setForwardSecrecy(false);
                }
                simulatedClient.setSupportedRsaKeyLengthList(clientConfig.getSupportedRsaKeyLengthList());
                simulatedClient.setSupportedDheKeyLengthList(clientConfig.getSupportedDheKeyLengthList());
                simulatedClient.setSelectedCompressionMethod(context.getSelectedCompressionMethod());
                if (context.getNegotiatedExtensionSet() != null && !context.getNegotiatedExtensionSet().isEmpty()) {
                    simulatedClient.setNegotiatedExtensions(context.getNegotiatedExtensionSet().toString());
                }
                if (clientConfig.getConfig().isAddAlpnExtension()) {
                    simulatedClient.setAlpnAnnouncedProtocols(Arrays.toString(clientConfig.getConfig().getAlpnAnnouncedProtocols()));
                } else {
                    simulatedClient.setAlpnAnnouncedProtocols("-");
                }
            }
            simulatedClient.setReceivedCertificate(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace));
            if (simulatedClient.getReceivedCertificate()) {
                if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")
                        && context.getServerRSAPublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerRSAPublicKey().bitLength()));
                }
            }
            simulatedClient.setReceivedServerKeyExchange(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace));
            if (simulatedClient.getReceivedServerKeyExchange()) {
                if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_DH")
                        && context.getServerDhPublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerDhPublicKey().bitLength()));
                } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_ECDH")
                        && context.getServerEcPublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerEcPublicKey().getByteX().length * 8));
                    simulatedClient.setSelectedNamedGroup(context.getSelectedGroup().name());
                } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_PSK")
                        && context.getServerPSKPublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerPSKPublicKey().bitLength()));
                } else if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_SRP")
                        && context.getServerSRPPublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerSRPPublicKey().bitLength()));
                } else if (simulatedClient.getSelectedCiphersuite().usesGOSTR3411()
                        && context.getServerGostEc01PublicKey() != null) {
                    simulatedClient.setServerPublicKeyLength(Integer.toString(context.getServerGostEc01PublicKey().getByteX().length * 8));
                }
            }
            simulatedClient.setReceivedCertificateRequest(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, trace));
            simulatedClient.setReceivedServerHelloDone(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace));
            if (simulatedClient.getReceivedServerHelloDone()) {
                simulatedClient.setHandshakeSuccessful(true);
                simulatedClient.setServerPublicKeyLengthAccept(true);
                if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_RSA")
                        && simulatedClient.getSupportedRsaKeyLengthList() != null
                        && !simulatedClient.getSupportedRsaKeyLengthList().contains(simulatedClient.getServerPublicKeyLength())) {
                    simulatedClient.setHandshakeSuccessful(false);
                    simulatedClient.setServerPublicKeyLengthAccept(false);
                }
                if (simulatedClient.getSelectedCiphersuite().name().contains("TLS_DHE_RSA")
                        && simulatedClient.getSupportedDheKeyLengthList() != null
                        && !simulatedClient.getSupportedDheKeyLengthList().contains(simulatedClient.getServerPublicKeyLength())) {
                    simulatedClient.setHandshakeSuccessful(false);
                    simulatedClient.setServerPublicKeyLengthAccept(false);
                }
                if (simulatedClient.getServerPublicKeyLengthAccept() == false) {
                    simulatedClient.setHandshakeFailedBecause("Server public key length ("
                            + simulatedClient.getServerPublicKeyLength() + ") probably not supported by client");
                }
            } else {
                simulatedClient.setHandshakeSuccessful(false);
                simulatedClient.setHandshakeFailedBecause("Server did not send message: ServerHelloDone");
                if (!simulatedClient.getReceivedServerHello()) {
                    simulatedClient.setHandshakeFailedBecause("Server did not send messages: ServerHello, ServerHelloDone");
                }
            }
            simulatedClientList.add(simulatedClient);
        } catch (Exception ex) {
            throw new RuntimeException(clientConfig.getType() + ":" + clientConfig.getVersion(), ex);
        }
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
