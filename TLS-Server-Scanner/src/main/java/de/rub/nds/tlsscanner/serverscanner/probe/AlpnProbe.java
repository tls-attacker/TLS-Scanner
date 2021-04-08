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
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpnProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AlpnProbe extends TlsProbe {

    public AlpnProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.ALPN, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<String> supportedAlpnProtocols = getSupportedAlpnProtocols();
            return new AlpnProbeResult(supportedAlpnProtocols);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new AlpnProbeResult(null);
        }
    }

    private List<String> getSupportedAlpnProtocols() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        List<CipherSuite> ciphersuites = new LinkedList<>();
        ciphersuites.addAll(Arrays.asList(CipherSuite.values()));
        ciphersuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        ciphersuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setDefaultClientSupportedCipherSuites(ciphersuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.values());
        tlsConfig.setAddAlpnExtension(true);
        List<String> alpnProtocols = new LinkedList<>();
        for (AlpnProtocol protocol : AlpnProtocol.values()) {
            if (!protocol.isGrease()) {
                alpnProtocols.add(protocol.getConstant());
            }
        }
        tlsConfig.setDefaultProposedAlpnProtocols(alpnProtocols);

        String selectedAlpnProtocol;
        List<String> supportedAlpnProtocols = new LinkedList<>();
        List<String> toTestList = new LinkedList<>();
        for (AlpnProtocol protocol : AlpnProtocol.values()) {
            toTestList.add(protocol.getConstant());
        }
        do {
            selectedAlpnProtocol = testAlpns(toTestList, tlsConfig);
            if (!toTestList.contains(selectedAlpnProtocol)) {
                LOGGER.debug("Server chose a protocol we did not offer!");
                break;
            }
            if (selectedAlpnProtocol != null) {
                supportedAlpnProtocols.add(selectedAlpnProtocol);
                toTestList.remove(selectedAlpnProtocol);
            }
        } while (selectedAlpnProtocol != null || toTestList.size() > 0);
        return supportedAlpnProtocols;
    }

    private String testAlpns(List<String> alpnList, Config tlsConfig) {
        tlsConfig.setDefaultProposedAlpnProtocols(alpnList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedAlpnProtocol();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.EXTENSIONS)
            && report.getSupportedExtensions().contains(ExtensionType.ALPN);

    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new AlpnProbeResult(new LinkedList<>());
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }
}
