/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ResumptionResult;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class ResumptionProbe extends TlsProbe {

    private List<CipherSuite> supportedSuites;

    public ResumptionProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RESUMPTION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> ciphersuites = new LinkedList<>();
            ciphersuites.addAll(supportedSuites);
            // TODO this can fail in some rare occasions
            tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites.get(0));
            tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setEnforceSettings(false);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopActionsAfterIOException(true);
            tlsConfig.setStopReceivingAfterFatal(true);
            tlsConfig.setStopActionsAfterFatal(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_RESUMPTION);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            State state = new State(tlsConfig);
            executeState(state);
            return new ResumptionResult(state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE
                    : TestResult.FALSE);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new ResumptionResult(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCipherSuites() != null && (report.getCipherSuites().size() > 0);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty()) {
            supportedSuites = new ArrayList<>(report.getCipherSuites());
        } else {
            supportedSuites = CipherSuite.getImplemented();
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new ResumptionResult(TestResult.COULD_NOT_TEST);
    }
}
