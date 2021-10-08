/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.probe.result.BasicProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class BasicProbe extends TlsProbe<ClientReport, BasicProbeResult> {

    public BasicProbe(ParallelExecutor parallelExecutor, ScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.BASIC, scannerConfig);
    }

    @Override
    public BasicProbeResult executeTest() {
        Config config = scannerConfig.createConfig();
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
        State state = new State(config, trace);
        executeState(state);
        if (trace.executedAsPlanned()) {
            List<CipherSuite> clientSupportedCipherSuites = state.getTlsContext().getClientSupportedCipherSuites();
            List<CompressionMethod> clientSupportedCompressions =
                state.getTlsContext().getClientSupportedCompressions();
            List<SignatureAndHashAlgorithm> clientSupportedSignatureAndHashAlgorithms =
                state.getTlsContext().getClientSupportedSignatureAndHashAlgorithms();
            Set<ExtensionType> clientProposedExtensions = state.getTlsContext().getProposedExtensions();
            List<NamedGroup> clientNamedGroupsList = state.getTlsContext().getClientNamedGroupsList();
            List<ECPointFormat> clientPointFormatsList = state.getTlsContext().getClientPointFormatsList();
            return new BasicProbeResult(clientSupportedCipherSuites, clientSupportedCompressions,
                clientSupportedSignatureAndHashAlgorithms, clientProposedExtensions, clientNamedGroupsList,
                getKeyShareGroups(trace),
                clientPointFormatsList);
        } else {
            return getCouldNotExecuteResult();
        }
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public BasicProbeResult getCouldNotExecuteResult() {
        return new BasicProbeResult(null, null, null, null, null, null, null);
    }

    @Override
    public void adjustConfig(ClientReport report) {
    }
    
    private List<NamedGroup> getKeyShareGroups(WorkflowTrace executedTrace) {
        ClientHelloMessage receivedClientHello = (ClientHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.CLIENT_HELLO, executedTrace);
        List keyShareGroups = new LinkedList<>();
        if(receivedClientHello.containsExtension(ExtensionType.KEY_SHARE)) {
            KeyShareExtensionMessage keyShareExtension = receivedClientHello.getExtension(KeyShareExtensionMessage.class);
            keyShareExtension.getKeyShareList().stream().forEach(keyShareGroups::add);
        }
        return keyShareGroups;
    }

}
