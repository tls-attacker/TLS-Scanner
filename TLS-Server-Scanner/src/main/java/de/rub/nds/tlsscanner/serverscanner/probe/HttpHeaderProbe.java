/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HttpHeaderResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class HttpHeaderProbe extends HttpsProbe {

    public HttpHeaderProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HTTP_HEADER, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
            cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
            cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            tlsConfig.setQuickReceive(true);
            tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setEnforceSettings(false);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopReceivingAfterFatal(true);
            tlsConfig.setStopActionsAfterFatal(true);
            tlsConfig.setHttpsParsingEnabled(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.HTTPS);
            tlsConfig.setStopActionsAfterIOException(true);
            // Don't send extensions if we are in SSLv2
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(true);

            List<NamedGroup> namedGroups = NamedGroup.getImplemented();
            namedGroups.remove(NamedGroup.ECDH_X25519);
            tlsConfig.setDefaultClientNamedGroups(namedGroups);
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
            trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
            trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(new SendAction(this.getHttpsRequest()));
            trace.addTlsAction(new ReceiveAction(new HttpsResponseMessage()));
            State state = new State(tlsConfig, trace);
            executeState(state);
            ReceivingAction action = trace.getLastReceivingAction();
            HttpsResponseMessage responseMessage = null;
            if (action.getReceivedMessages() != null) {
                for (ProtocolMessage message : action.getReceivedMessages()) {
                    if (message instanceof HttpsResponseMessage) {
                        responseMessage = (HttpsResponseMessage) message;
                        break;
                    }
                }
            }
            boolean speaksHttps = responseMessage != null;
            List<HttpsHeader> headerList;
            if (speaksHttps) {
                headerList = responseMessage.getHeader();
            } else {
                headerList = new LinkedList<>();
            }
            return new HttpHeaderResult(speaksHttps == true ? TestResult.TRUE : TestResult.FALSE, headerList);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new HttpHeaderResult(TestResult.ERROR_DURING_TEST, new LinkedList<HttpsHeader>());
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new HttpHeaderResult(TestResult.COULD_NOT_TEST, null);
    }
}
