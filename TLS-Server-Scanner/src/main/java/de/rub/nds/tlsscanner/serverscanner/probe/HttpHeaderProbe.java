/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
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

public class HttpHeaderProbe
        extends TlsServerProbe<ConfigSelector, ServerReport, HttpHeaderResult> {

    public HttpHeaderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_HEADER, configSelector);
    }

    @Override
    public HttpHeaderResult executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
        State state = new State(tlsConfig);
        executeState(state);

        ReceivingAction action = state.getWorkflowTrace().getLastReceivingAction();
        HttpResponseMessage responseMessage = null;
        if (action.getReceivedHttpMessages() != null) {
            for (HttpMessage httpMsg : action.getReceivedHttpMessages()) {
                if (httpMsg instanceof HttpResponseMessage) {
                    responseMessage = (HttpResponseMessage) httpMsg;
                    break;
                }
            }
        }
        boolean speaksHttps = responseMessage != null;
        List<HttpHeader> headerList;
        if (speaksHttps) {
            headerList = responseMessage.getHeader();
        } else {
            headerList = new LinkedList<>();
        }
        return new HttpHeaderResult(
                speaksHttps == true ? TestResults.TRUE : TestResults.FALSE, headerList);
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public HttpHeaderResult getCouldNotExecuteResult() {
        return new HttpHeaderResult(TestResults.COULD_NOT_TEST, null);
    }
}
