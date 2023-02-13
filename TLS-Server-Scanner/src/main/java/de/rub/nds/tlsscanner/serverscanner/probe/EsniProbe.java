/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.EsniResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class EsniProbe extends TlsServerProbe<ConfigSelector, ServerReport, EsniResult> {

    public EsniProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.ESNI, configSelector);
    }

    @Override
    public EsniResult executeTest() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(false);
        tlsConfig.setAddEncryptedServerNameIndicationExtension(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        // ESNI stuff is in a bad state and only works with X25519 on our end
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.ECDH_X25519);
        tlsConfig.setDefaultClientKeyShareNamedGroups(NamedGroup.ECDH_X25519);
        State state = new State(tlsConfig);
        executeState(state);

        TlsContext context = state.getTlsContext();
        boolean isDnsKeyRecordAvailable = context.getEsniRecordBytes() != null;
        boolean isReceivedCorrectNonce =
                context.getEsniServerNonce() != null
                        && Arrays.equals(
                                context.getEsniServerNonce(), context.getEsniClientNonce());
        if (!WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return new EsniResult(TestResults.ERROR_DURING_TEST);
        } else if (isDnsKeyRecordAvailable && isReceivedCorrectNonce) {
            return (new EsniResult(TestResults.TRUE));
        } else {
            return (new EsniResult(TestResults.FALSE));
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION)
                && report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public EsniResult getCouldNotExecuteResult() {
        return new EsniResult(TestResults.COULD_NOT_TEST);
    }
}
