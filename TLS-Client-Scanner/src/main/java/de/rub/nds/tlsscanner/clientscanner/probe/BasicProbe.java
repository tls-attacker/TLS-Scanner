/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
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
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class BasicProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

    private List<CipherSuite> clientAdvertisedCipherSuites = null;
    private List<CompressionMethod> clientAdvertisedCompressions = null;
    private List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms = null;
    private Set<ExtensionType> clientAdvertisedExtensions = null;
    private List<NamedGroup> clientAdvertisedNamedGroupsList = null;
    private List<NamedGroup> clientKeyShareNamedGroupsList = null;
    private List<ECPointFormat> clientAdvertisedPointFormatsList = null;

    public BasicProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.BASIC, scannerConfig);
        register(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS,
                TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS);
    }

    @Override
    public void executeTest() {
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
            clientSupportedSignatureAndHashAlgorithms =
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
    public void adjustConfig(ClientReport report) {}

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES, clientAdvertisedCipherSuites);
        put(TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS, clientAdvertisedCompressions);
        put(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                clientSupportedSignatureAndHashAlgorithms);
        put(TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS, clientAdvertisedExtensions);
        put(TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS, clientAdvertisedNamedGroupsList);
        put(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS,
                clientKeyShareNamedGroupsList);
        put(TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS, clientAdvertisedPointFormatsList);
    }
}
