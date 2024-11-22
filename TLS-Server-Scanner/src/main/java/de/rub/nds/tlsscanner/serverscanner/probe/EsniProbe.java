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
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.EsniKeyDnsRequestAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class EsniProbe extends TlsServerProbe {

    private TestResult receivedCorrectNonce = TestResults.COULD_NOT_TEST;

    public EsniProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.ESNI, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_ESNI);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(false);
        tlsConfig.setAddEncryptedServerNameIndicationExtension(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        // ESNI stuff is in a bad state and only works with X25519 on our end
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultClientKeyShareNamedGroups(NamedGroup.ECDH_X25519);
        State state = new State(tlsConfig);
        executeState(state);
        TlsAction firstFailedAction =
                WorkflowTraceResultUtil.getFirstFailedAction(state.getWorkflowTrace());

        TlsContext context = state.getTlsContext();
        boolean isDnsKeyRecordAvailable = context.getEsniRecordBytes() != null;
        boolean isReceivedCorrectNonce =
                context.getEsniServerNonce() != null
                        && Arrays.equals(
                                context.getEsniServerNonce(), context.getEsniClientNonce());
        if (!WorkflowTraceResultUtil.didReceiveMessage(
                        state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)
                && !EsniKeyDnsRequestAction.class.equals(firstFailedAction.getClass())) {
            receivedCorrectNonce = TestResults.ERROR_DURING_TEST;
        } else if (isDnsKeyRecordAvailable && isReceivedCorrectNonce) {
            receivedCorrectNonce = TestResults.TRUE;
        } else {
            receivedCorrectNonce = TestResults.FALSE;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ServerReport>(ProtocolType.DTLS)
                .and(new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION))
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_TLS_1_3));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_ESNI, receivedCorrectNonce);
    }
}
