/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.HttpHeaderResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class HttpHeaderProbe extends TlsServerProbe<ConfigSelector, ServerReport, HttpHeaderResult> {

    public HttpHeaderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_HEADER, configSelector);
    }

    @Override
    public HttpHeaderResult executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setHttpsParsingEnabled(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
        State state = new State(tlsConfig);
        executeState(state);

        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
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
        return new HttpHeaderResult(speaksHttps == true ? TestResults.TRUE : TestResults.FALSE, headerList);
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public HttpHeaderResult getCouldNotExecuteResult() {
        return new HttpHeaderResult(TestResults.COULD_NOT_TEST, null);
    }
}
