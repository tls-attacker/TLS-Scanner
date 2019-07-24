/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.RenegotiationResult;
import de.rub.nds.tlsscanner.report.result.ResumptionResult;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 *
 * @author robert
 */
public class RenegotiationProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsRenegotiationExtension;

    public RenegotiationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RENEGOTIATION, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {
       try {
            TestResult supportsSecureRenegotiation;
            if (supportsRenegotiationExtension == TestResult.TRUE) {
                supportsSecureRenegotiation = supportsSecureClientRenegotiation();
            } else {
                supportsSecureRenegotiation = TestResult.FALSE;
            }
            TestResult supportsInsecureRenegotiation = supportsInsecureClientRenegotiation();
            return new RenegotiationResult(supportsSecureRenegotiation, supportsInsecureRenegotiation);
        } catch(Exception e) {
            return new RenegotiationResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult supportsSecureClientRenegotiation() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(supportedSuites);
        //TODO this can fail in some rare occasions
        tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites.get(0));
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.getDefaultClientNamedGroups().remove(NamedGroup.ECDH_X25519);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
    }

    private TestResult supportsInsecureClientRenegotiation() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(supportedSuites);
        //TODO this can fail in some rare occasions
        tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites.get(0));
        tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(false);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.getDefaultClientNamedGroups().remove(NamedGroup.ECDH_X25519);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return (report.getCipherSuites() != null && report.getCipherSuites().size() > 0);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
        supportsRenegotiationExtension = report.getResult(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION);
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new ResumptionResult(TestResult.COULD_NOT_TEST);
    }

}
