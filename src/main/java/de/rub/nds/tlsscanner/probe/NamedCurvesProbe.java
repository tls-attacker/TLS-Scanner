/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.NamedGroupResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class NamedCurvesProbe extends TlsProbe {

    public NamedCurvesProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        List<NamedGroup> groups = getSupportedNamedGroups();
        return new NamedGroupResult(groups);
    }

    private List<NamedGroup> getSupportedNamedGroups() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(getEcCiphersuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        List<NamedGroup> toTestList = new ArrayList<>(Arrays.asList(NamedGroup.values()));
        NamedGroup selectedGroup;
        List<NamedGroup> supportedNamedCurves = new LinkedList<>();
        do {
            selectedGroup = testCurves(toTestList, tlsConfig);
            if (!toTestList.contains(selectedGroup)) {
                LOGGER.debug("Server chose a Curve we did not offer!");
                break;
            }
            if (selectedGroup != null) {
                supportedNamedCurves.add(selectedGroup);
                toTestList.remove(selectedGroup);
            }
        } while (selectedGroup != null || toTestList.size() > 0);
        return supportedNamedCurves;
    }

    private NamedGroup testCurves(List<NamedGroup> curveList, Config tlsConfig) {
        tlsConfig.setDefaultClientNamedGroups(curveList);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedGroup();
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private List<CipherSuite> getEcCiphersuites() {
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.name().contains("ECDH")) {
                suiteList.add(suite);
            }
        }
        return suiteList;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }
}
