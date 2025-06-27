/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ServerOptionsRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApplicationLayerProbe extends TlsServerProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<ApplicationProtocol> supportedApplications;
    private TestResult speaksHttp = TestResults.COULD_NOT_TEST;

    public ApplicationLayerProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.APPLICATION_LAYER, configSelector);
        register(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, TlsAnalyzedProperty.SPEAKS_HTTP);
    }

    @Override
    protected void executeTest() {
        supportedApplications = new ArrayList<>();
        speaksHttp = TestResults.FALSE;

        // Test for HTTP
        if (isHttpSupported()) {
            supportedApplications.add(ApplicationProtocol.HTTP);
            speaksHttp = TestResults.TRUE;
        }
    }

    private boolean isHttpSupported() {
        // Send an HTTP GET request
        String httpRequest =
                "GET / HTTP/1.1\r\nHost: "
                        + configSelector.getScannerConfig().getClientDelegate().getHost()
                        + "\r\nConnection: close\r\n\r\n";
        byte[] requestData = httpRequest.getBytes(StandardCharsets.UTF_8);

        byte[] responseData = sendApplicationData(requestData);

        if (responseData.length > 0) {
            String response = new String(responseData, StandardCharsets.UTF_8);
            // Check for HTTP response pattern
            if (response.contains("HTTP/")
                    && (response.contains("200")
                            || response.contains("301")
                            || response.contains("302")
                            || response.contains("403")
                            || response.contains("404")
                            || response.contains("500")
                            || response.contains("503"))) {
                LOGGER.debug(
                        "HTTP response detected: "
                                + response.substring(0, Math.min(response.length(), 100)));
                return true;
            }
        }

        return false;
    }

    private byte[] sendApplicationData(byte[] data) {
        Config config = configSelector.getAnyWorkingBaseConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(new ApplicationMessage(data)));
        ReceiveAction receiveAction = new ReceiveAction(new ApplicationMessage());
        trace.addTlsAction(receiveAction);

        State state = new State(config, trace);
        executeState(state);

        if (receiveAction.getReceivedRecords() != null
                && !receiveAction.getReceivedRecords().isEmpty()) {
            ByteArrayOutputStream receivedData = new ByteArrayOutputStream();
            try {
                for (Record record : receiveAction.getReceivedRecords()) {
                    receivedData.write(record.getCleanProtocolMessageBytes().getValue());
                }
            } catch (IOException ex) {
                LOGGER.error("Could not write cleanProtocolMessageBytes to receivedData", ex);
            }
            return receivedData.toByteArray();
        } else {
            ProtocolMessage receivedMessage =
                    WorkflowTraceResultUtil.getLastReceivedMessage(state.getWorkflowTrace());
            if (receivedMessage instanceof ApplicationMessage) {
                ApplicationMessage appMessage = (ApplicationMessage) receivedMessage;
                if (appMessage.getData() != null && appMessage.getData().getValue() != null) {
                    return appMessage.getData().getValue();
                }
            }
        }

        return new byte[0];
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        if (!supportedApplications.isEmpty()) {
            @SuppressWarnings("unchecked")
            List<ApplicationProtocol> existingApplications =
                    (List<ApplicationProtocol>)
                            report.getResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS);
            if (existingApplications != null) {
                // Merge with existing applications (e.g., from DTLS probe)
                for (ApplicationProtocol app : supportedApplications) {
                    if (!existingApplications.contains(app)) {
                        existingApplications.add(app);
                    }
                }
                put(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, existingApplications);
            } else {
                put(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS, supportedApplications);
            }
        }
        put(TlsAnalyzedProperty.SPEAKS_HTTP, speaksHttp);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ServerOptionsRequirement(configSelector.getScannerConfig(), getType());
    }
}
