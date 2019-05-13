/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
    private boolean supportsRenegotiationExtension;

    public RenegotiationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RENEGOTIATION, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {

        boolean supportsSecureRenegotiation;
        if (supportsRenegotiationExtension == Boolean.TRUE) {
            supportsSecureRenegotiation = supportsSecureClientRenegotiation();
        } else {
            supportsSecureRenegotiation = false;
        }
        boolean supportsInsecureRenegotiation = supportsInsecureClientRenegotiation();
        return new RenegotiationResult(supportsSecureRenegotiation, supportsInsecureRenegotiation);
    }

    private boolean supportsSecureClientRenegotiation() {
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
        return state.getWorkflowTrace().executedAsPlanned();
    }

    private boolean supportsInsecureClientRenegotiation() {
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
        return state.getWorkflowTrace().executedAsPlanned();
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return (report.getCipherSuites() != null && report.getCipherSuites().size() > 0);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
        supportsRenegotiationExtension = report.getSupportsSecureRenegotiation();
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new ResumptionResult(null);
    }

}
