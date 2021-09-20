/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateManager;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.probe.result.CcaRequiredResult;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.probe.result.ProbeResult;

public class CcaRequiredProbe extends TlsProbe<SiteReport, CcaRequiredResult> {

    public CcaRequiredProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, config);
    }

    @Override
    public ProbeResult executeTest() {
        CcaCertificateManager ccaCertificateManager = new CcaCertificateManager(getScannerConfig().getCcaDelegate());
        Config tlsConfig = generateConfig();
        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaCertificateManager,
            CcaWorkflowType.CRT_CKE_CCS_FIN, CcaCertificateType.EMPTY);
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return new CcaRequiredResult(TestResult.FALSE);
        } else {
            return new CcaRequiredResult(TestResult.TRUE);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return (report.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResult.TRUE);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public CcaRequiredResult getCouldNotExecuteResult() {
        return new CcaRequiredResult(TestResult.COULD_NOT_TEST);
    }

    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        return config;
    }
}
