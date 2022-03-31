/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpnResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class AlpnProbe extends TlsProbe {

    public AlpnProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.ALPN, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        List<String> supportedAlpnProtocols = getSupportedAlpnProtocols();
        return new AlpnResult(supportedAlpnProtocols);

    }

    private List<String> getSupportedAlpnProtocols() {
        Config tlsConfig = getConfigSelector().getBaseConfig();
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
        return new AlpnResult(null);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }
}
