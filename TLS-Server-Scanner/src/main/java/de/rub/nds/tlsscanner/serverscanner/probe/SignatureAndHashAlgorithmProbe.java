/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SignatureAndHashAlgorithmResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class SignatureAndHashAlgorithmProbe extends TlsProbe {

    private List<ProtocolVersion> versions;

    public SignatureAndHashAlgorithmProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SIGNATURE_AND_HASH, config);
    }

    @Override
    public ProbeResult executeTest() {
        List<SignatureAndHashAlgorithm> supported = new ArrayList<>();
        for (ProtocolVersion version : this.versions) {
            Config tlsConfig = this.getBasicConfig();
            tlsConfig.setHighestProtocolVersion(version);
            tlsConfig.setDefaultClientSupportedCipherSuites(ProtocolVersion.TLS13.equals(version)
                ? CipherSuite.getImplementedTls13CipherSuites() : CipherSuite.getImplemented());

            List<SignatureAndHashAlgorithm> toTestList =
                new ArrayList<>(Arrays.asList(SignatureAndHashAlgorithm.values()));
            toTestList.removeAll(supported);
            TlsContext context;

            do {
                context = this.testAlgorithms(toTestList, tlsConfig);
                if (context != null) {
                    SignatureAndHashAlgorithm selected = context.getSelectedSignatureAndHashAlgorithm();
                    supported.add(selected);
                    if (!toTestList.contains(selected)) {
                        break;
                    }
                    toTestList.remove(selected);
                }
            } while (context != null && toTestList.size() > 0);
        }
        return new SignatureAndHashAlgorithmResult(supported);
    }

    private TlsContext testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);

        return tlsConfig;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.versions = report.getVersions();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SignatureAndHashAlgorithmResult(null);
    }
}
