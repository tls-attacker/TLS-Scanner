/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HttpHeaderResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class HttpHeaderProbe extends HttpsProbe {

    public HttpHeaderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HTTP_HEADER, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        Config tlsConfig = getConfigSelector().getBaseConfig();
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
        return new HttpHeaderResult(speaksHttps == true ? TestResult.TRUE : TestResult.FALSE, headerList);
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
