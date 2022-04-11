/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.clientscanner.probe.result.Version13RandomResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Version13RandomProbe extends TlsProbe<ClientScannerConfig, ClientReport, Version13RandomResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte[] SERVER_RANDOM_12_POSTFIX = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
    private static final byte[] SERVER_RANDOM_PRE_12_POSTFIX = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };

    private final Random random = new Random();

    public Version13RandomProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.VERSION_1_3_RANDOM_DOWNGRADE, scannerConfig);
    }

    @Override
    public Version13RandomResult executeTest() {
        boolean tls10Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS10);
        boolean tls11Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS11);
        boolean tls12Rejected = testIfDownGradeEnforcedProtocolVersion(ProtocolVersion.TLS12);
        if (tls10Rejected && tls11Rejected && tls12Rejected) {
            return new Version13RandomResult(TestResults.TRUE);
        } else {
            return new Version13RandomResult(TestResults.FALSE);
        }
    }

    private boolean testIfDownGradeEnforcedProtocolVersion(ProtocolVersion version) {
        Config config = getScannerConfig().createConfig();
        config.setHighestProtocolVersion(version);
        config.setDefaultSelectedProtocolVersion(version);

        // patch randomness
        byte[] serverRandomPostfix;
        if (version == ProtocolVersion.TLS12) {
            serverRandomPostfix = SERVER_RANDOM_12_POSTFIX;
        } else {
            serverRandomPostfix = SERVER_RANDOM_PRE_12_POSTFIX;
        }
        byte[] serverRandomPrefix = new byte[HandshakeByteLength.RANDOM - serverRandomPostfix.length];
        byte[] serverRandom = new byte[HandshakeByteLength.RANDOM];
        random.nextBytes(serverRandomPrefix);
        System.arraycopy(serverRandomPrefix, 0, serverRandom, 0, serverRandomPrefix.length);
        System.arraycopy(serverRandomPostfix, 0, serverRandom, serverRandomPrefix.length, serverRandomPostfix.length);
        config.setDefaultServerRandom(serverRandom);
        config.setUseFreshRandom(false);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
            RunningModeType.SERVER);
        State state = new State(config, trace);
        executeState(state);
        return !state.getWorkflowTrace().executedAsPlanned();
    }

    @Override
    public Version13RandomResult getCouldNotExecuteResult() {
        return new Version13RandomResult(TestResults.CANNOT_BE_TESTED);
    }

    @Override
    public void adjustConfig(ClientReport report) {
    }

	@Override
	protected Requirement getRequirements(ClientReport report) {
        // TODO Check if atleast one non tls 1.3 version is supported
		return new ProbeRequirement(report);
	}

}
