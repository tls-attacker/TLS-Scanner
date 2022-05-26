/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;

public class EsniProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult receivedCorrectNonce;

    public EsniProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.ESNI, configSelector);
        super.register(TlsAnalyzedProperty.SUPPORTS_ESNI);
    }

    @Override
    public void executeTest() {
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
        boolean isReceivedCorrectNonce = context.getEsniServerNonce() != null
            && Arrays.equals(context.getEsniServerNonce(), context.getEsniClientNonce());
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) 
        	receivedCorrectNonce = TestResults.ERROR_DURING_TEST;
        else if (isDnsKeyRecordAvailable && isReceivedCorrectNonce) 
        	receivedCorrectNonce = TestResults.TRUE;
        else 
        	receivedCorrectNonce = TestResults.FALSE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.PROTOCOL_VERSION).requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_TLS_1_3);
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.SUPPORTS_ESNI, receivedCorrectNonce);
    }
}
