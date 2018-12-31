/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import static de.rub.nds.tlsscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConfigFileList;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailed;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.HandshakeSimulationResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class HandshakeSimulationProbe extends TlsProbe {

    private static final String RESOURCE_FOLDER = "/extracted_client_configs";

    private final List<SimulatedClient> simulatedClientList;

    public HandshakeSimulationProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HANDSHAKE_SIMULATION, config, 1);
        simulatedClientList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        TlsClientConfig tlsClientConfig;
        List<TlsClientConfig> tlsClientConfigList = new LinkedList<>();
        List<State> clientStateList = new LinkedList<>();
        ConfigFileList configFileList = ConfigFileList.loadConfigFileList("/" + ConfigFileList.FILE_NAME);
        for (String configFileName : configFileList.getFiles()) {
            tlsClientConfig = TlsClientConfig.createTlsClientConfig(RESOURCE_FOLDER + "/" + configFileName);
            tlsClientConfigList.add(tlsClientConfig);
            clientStateList.add(getPreparedClientState(tlsClientConfig));
        }
        parallelExecutor.bulkExecute(clientStateList);
        for (int i = 0; i < tlsClientConfigList.size(); i++) {
            simulatedClientList.add(getSimulatedClient(tlsClientConfigList.get(i), clientStateList.get(i)));
        }
        return new HandshakeSimulationResult(simulatedClientList);
    }

    private State getPreparedClientState(TlsClientConfig clientConfig) {
        Config config = clientConfig.getConfig();
        getScannerConfig().getClientDelegate().applyDelegate(config);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
        config.setStopRecievingAfterFatal(true);
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
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        State state = new State(config, trace);
        return state;
    }

    private SimulatedClient getSimulatedClient(TlsClientConfig tlsClientConfig, State state) {
        SimulatedClient simulatedClient = new SimulatedClient(tlsClientConfig.getType(),
                tlsClientConfig.getVersion(), tlsClientConfig.isDefaultVersion());
        evaluateClientConfig(tlsClientConfig, simulatedClient);
        evaluateReceivedMessages(state, simulatedClient);
        return simulatedClient;
    }

    private void evaluateClientConfig(TlsClientConfig tlsClientConfig, SimulatedClient simulatedClient) {
        Config config = tlsClientConfig.getConfig();
        simulatedClient.setHighestClientProtocolVersion(config.getHighestProtocolVersion());
        simulatedClient.setClientSupportedCiphersuites(config.getDefaultClientSupportedCiphersuites());
        if (config.isAddAlpnExtension()) {
            simulatedClient.setAlpnAnnouncedProtocols(Arrays.toString(config.getAlpnAnnouncedProtocols()));
        } else {
            simulatedClient.setAlpnAnnouncedProtocols("-");
        }
        simulatedClient.setSupportedVersionList(tlsClientConfig.getSupportedVersionList());
        simulatedClient.setVersionAcceptForbiddenCiphersuiteList(tlsClientConfig.getVersionAcceptForbiddenCiphersuiteList());
        simulatedClient.setSupportedRsaKeySizeList(tlsClientConfig.getSupportedRsaKeySizeList());
        simulatedClient.setSupportedDheKeySizeList(tlsClientConfig.getSupportedDheKeySizeList());
    }

    private void evaluateReceivedMessages(State state, SimulatedClient simulatedClient) {
        WorkflowTrace trace = state.getWorkflowTrace();
        simulatedClient.setReceivedServerHello(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace));
        simulatedClient.setReceivedCertificate(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace));
        simulatedClient.setReceivedServerKeyExchange(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, trace));
        simulatedClient.setReceivedCertificateRequest(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, trace));
        simulatedClient.setReceivedServerHelloDone(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace));
        simulatedClient.setReceivedAlert(WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, trace));
        simulatedClient.setReceivedUnknown(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.UNKNOWN, trace));
        if (simulatedClient.getReceivedAlert()) {
            simulatedClient.setHandshakeSuccessful(false);
        } else {
            boolean receivedAllMandatoryMessages = true;
            if (!simulatedClient.getReceivedServerHello()) {
                receivedAllMandatoryMessages = false;
            }
            if (!simulatedClient.getReceivedCertificate()) {
                receivedAllMandatoryMessages = false;
            }
            if (simulatedClient.getKeyExchangeAlgorithm() != null) {
                switch (simulatedClient.getKeyExchangeAlgorithm()) {
                    case DHE_DSS:
                    case DHE_RSA:
                    case DH_ANON:
                    case ECDHE_ECDSA:
                    case ECDHE_RSA:
                    case ECDH_ANON:
                        if (!simulatedClient.getReceivedServerKeyExchange()) {
                            receivedAllMandatoryMessages = false;
                        }
                        break;
                    default:
                        break;
                }
            }
            if (!simulatedClient.getReceivedServerHelloDone()) {
                receivedAllMandatoryMessages = false;
            }
            TlsContext context = state.getTlsContext();
            if (receivedAllMandatoryMessages) {
                evaluateServerHello(context, simulatedClient);
                evaluateCertificate(context, simulatedClient);
                if (simulatedClient.getReceivedServerKeyExchange()) {
                    evaluateServerKeyExchange(context, simulatedClient);
                }
            } else {
                simulatedClient.addToFailReasons(HandshakeFailed.PARSING_ERROR.getReason());
            }
        }
    }

    private void evaluateServerHello(TlsContext context, SimulatedClient simulatedClient) {
        simulatedClient.setSelectedProtocolVersion(context.getSelectedProtocolVersion());
        CipherSuite cipherSuite = context.getSelectedCipherSuite();
        simulatedClient.setSelectedCiphersuite(cipherSuite);
        if (cipherSuite.isEphemeral()) {
            simulatedClient.setForwardSecrecy(true);
        } else {
            simulatedClient.setForwardSecrecy(false);
        }
        simulatedClient.setKeyExchangeAlgorithm(AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite));
        simulatedClient.setSelectedCompressionMethod(context.getSelectedCompressionMethod());
        if (context.getNegotiatedExtensionSet() != null) {
            if (!context.getNegotiatedExtensionSet().isEmpty()) {
                simulatedClient.setNegotiatedExtensions(context.getNegotiatedExtensionSet().toString());
            } else {
                simulatedClient.setNegotiatedExtensions("-");
            }
        }
    }

    private void evaluateCertificate(TlsContext context, SimulatedClient simulatedClient) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeRsa()) {
            simulatedClient.setServerPublicKeyParameter(getRsaPublicKeyFromCert(context.getServerCertificate()));
        }
    }

    private void evaluateServerKeyExchange(TlsContext context, SimulatedClient simulatedClient) {
        if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeDh() && context.getServerDhPublicKey() != null) {
            simulatedClient.setServerPublicKeyParameter(context.getServerDhModulus().bitLength());
        } else if (simulatedClient.getKeyExchangeAlgorithm().isKeyExchangeEcdh()) {
            if (context.getSelectedGroup() != null) {
                simulatedClient.setSelectedNamedGroup(context.getSelectedGroup().name());
                if (context.getSelectedGroup().getCoordinateSizeInBit() != null) {
                    simulatedClient.setServerPublicKeyParameter(context.getSelectedGroup().getCoordinateSizeInBit());
                }
            }
            if (simulatedClient.getServerPublicKeyParameter() == null) {
                if (context.getServerEcPublicKey() != null) {
                    simulatedClient.setServerPublicKeyParameter(context.getServerEcPublicKey().getByteX().length * 8);
                }
            }
        }
    }

    private Integer getRsaPublicKeyFromCert(Certificate certs) {
        try {
            if (certs != null) {
                for (org.bouncycastle.asn1.x509.Certificate cert : certs.getCertificateList()) {
                    X509Certificate x509Cert = new X509CertificateObject(cert);
                    if (x509Cert.getPublicKey() != null) {
                        RSAPublicKey rsaPk = (RSAPublicKey) x509Cert.getPublicKey();
                        return rsaPk.getModulus().bitLength();
                    }
                }
            }
        } catch (CertificateParsingException ex) {
            LOGGER.warn("Could not parse public key from certificate", ex);
        }
        return null;
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
