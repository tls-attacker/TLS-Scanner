/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.BasicResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class BasicProbe extends TlsClientProbe<ClientScannerConfig, ClientReport, BasicResult> {

    private List<CipherSuite> clientAdvertisedCipherSuites = null;
    private List<CompressionMethod> clientAdvertisedCompressions = null;
    private List<SignatureAndHashAlgorithm> clientAdvertisedSignatureAndHashAlgorithms = null;
    private Set<ExtensionType> clientAdvertisedExtensions = null;
    private List<NamedGroup> clientAdvertisedNamedGroupsList = null;
    private List<NamedGroup> clientKeyShareNamedGroupsList = null;
    private List<ECPointFormat> clientAdvertisedPointFormatsList = null;

    public BasicProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.BASIC, scannerConfig);
    }

    @Override
    public BasicResult executeTest() {
        receiveClientHello();

        return new BasicResult(
                clientAdvertisedCipherSuites,
                clientAdvertisedCompressions,
                clientAdvertisedSignatureAndHashAlgorithms,
                clientAdvertisedExtensions,
                clientAdvertisedNamedGroupsList,
                clientKeyShareNamedGroupsList,
                clientAdvertisedPointFormatsList);
    }

    public void receiveClientHello() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            TlsContext traceContext = state.getTlsContext();
            clientAdvertisedCipherSuites = traceContext.getClientSupportedCipherSuites();
            clientAdvertisedCompressions = traceContext.getClientSupportedCompressions();
            clientAdvertisedSignatureAndHashAlgorithms =
                    traceContext.getClientSupportedSignatureAndHashAlgorithms();
            clientAdvertisedExtensions = traceContext.getProposedExtensions();
            clientAdvertisedNamedGroupsList = traceContext.getClientNamedGroupsList();
            clientAdvertisedPointFormatsList = traceContext.getClientPointFormatsList();

            ClientHelloMessage receivedClientHello =
                    (ClientHelloMessage)
                            WorkflowTraceUtil.getFirstReceivedMessage(
                                    HandshakeMessageType.CLIENT_HELLO, state.getWorkflowTrace());
            clientKeyShareNamedGroupsList = getKeyShareGroups(receivedClientHello);
        }
    }

    private List<NamedGroup> getKeyShareGroups(ClientHelloMessage clientHello) {
        List<NamedGroup> keyShareGroups = new LinkedList<>();
        if (clientHello.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyShareExtension =
                    clientHello.getExtension(KeyShareExtensionMessage.class);
            keyShareExtension.getKeyShareList().stream()
                    .forEach(entry -> keyShareGroups.add(entry.getGroupConfig()));
        }
        return keyShareGroups;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public BasicResult getCouldNotExecuteResult() {
        return new BasicResult(null, null, null, null, null, null, null);
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
