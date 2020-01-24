/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaCertificateType;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CcaRequiredResult;
import de.rub.nds.tlsscanner.report.result.CcaSupportResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CcaRequiredProbe extends TlsProbe {
    private List<CipherSuite> suiteList;

    public CcaRequiredProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CCA_SUPPORT, config, 1);
        suiteList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {

        CcaDelegate ccaDelegate = (CcaDelegate) getScannerConfig().getDelegate(CcaDelegate.class);

        CertificateMessage certificateMessage = null;

        CcaWorkflowType ccaWorkflowType = CcaWorkflowType.CRT_CKE_CCS_FIN;
        CcaCertificateType ccaCertificateType = CcaCertificateType.EMPTY;
        Config tlsConfig = generateConfig();
        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaDelegate, ccaWorkflowType, ccaCertificateType);
        State state = new State(tlsConfig, trace);
        try {
            executeState(state);
        } catch (Exception E) {
            LOGGER.error("Could not test if client authentication is required.");
        }
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return new CcaRequiredResult(TestResult.FALSE);
        } else {
            return new CcaRequiredResult(TestResult.TRUE);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_CCA) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CcaRequiredResult(TestResult.COULD_NOT_TEST);
    }

    private Config generateConfig() {
        Config config = getScannerConfig().createConfig();
        config.setAutoSelectCertificate(false);
        config.setAddServerNameIndicationExtension(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
        config.setDefaultClientNamedGroups(namedGroups);

        return config;
    }
}
