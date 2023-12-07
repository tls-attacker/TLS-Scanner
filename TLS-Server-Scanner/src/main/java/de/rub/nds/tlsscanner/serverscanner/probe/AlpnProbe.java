/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ExtensionRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class AlpnProbe extends TlsServerProbe {

    private List<String> supportedAlpnProtocols;

    public AlpnProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.ALPN, configSelector);
        register(TlsAnalyzedProperty.SUPPORTED_ALPN_CONSTANTS);
    }

    @Override
    protected void executeTest() {
        supportedAlpnProtocols = getSupportedAlpnProtocols();
    }

    private List<String> getSupportedAlpnProtocols() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddAlpnExtension(true);

        String selectedAlpnProtocol;
        List<String> supportedAlpnProtocols = new LinkedList<>();
        List<String> toTestList = new LinkedList<>();
        for (AlpnProtocol protocol : AlpnProtocol.values()) {
            if (!protocol.isGrease()) {
                toTestList.add(protocol.getConstant());
            }
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
        } while (selectedAlpnProtocol != null || !toTestList.isEmpty());
        return supportedAlpnProtocols;
    }

    private String testAlpns(List<String> alpnList, Config tlsConfig) {
        tlsConfig.setDefaultProposedAlpnProtocols(alpnList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return state.getTlsContext().getSelectedAlpnProtocol();
        } else {
            LOGGER.debug(
                    "Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.EXTENSIONS)
                .and(new ExtensionRequirement<>(ExtensionType.ALPN));
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTED_ALPN_CONSTANTS, supportedAlpnProtocols);
    }
}
