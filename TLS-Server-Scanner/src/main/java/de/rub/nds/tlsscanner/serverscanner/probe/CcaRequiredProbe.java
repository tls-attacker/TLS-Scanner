/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.CcaCertificateManager;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaCertificateType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.trace.CcaWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.result.CcaRequiredResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaRequiredProbe
        extends TlsServerProbe<ConfigSelector, ServerReport, CcaRequiredResult> {

    public CcaRequiredProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, configSelector);
    }

    @Override
    public CcaRequiredResult executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAutoSelectCertificate(false);
        CcaCertificateManager ccaCertificateManager =
                new CcaCertificateManager(configSelector.getScannerConfig().getCcaDelegate());
        WorkflowTrace trace =
                CcaWorkflowGenerator.generateWorkflow(
                        tlsConfig,
                        ccaCertificateManager,
                        CcaWorkflowType.CRT_CKE_CCS_FIN,
                        CcaCertificateType.EMPTY);
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return new CcaRequiredResult(TestResults.FALSE);
        } else {
            return new CcaRequiredResult(TestResults.TRUE);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return (report.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE
                && configSelector.foundWorkingConfig());
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public CcaRequiredResult getCouldNotExecuteResult() {
        return new CcaRequiredResult(TestResults.COULD_NOT_TEST);
    }
}
