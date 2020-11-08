/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import com.fasterxml.jackson.core.Version;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe.VersionProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

public class VersionProbe13Random extends BaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte[] SERVER_RANDOM_12_POSTFIX = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 };
    private static final byte[] SERVER_RANDOM_PRE_12_POSTFIX = { 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00 };

    private static final List<CipherSuite> suites13;
    private static final List<CipherSuite> suitesPre13;
    static {
        suitesPre13 = CipherSuite.getImplemented();
        suitesPre13.removeIf((suite) -> suite.isTLS13());
        suites13 = CipherSuite.getImplemented();
        suites13.removeIf((suite) -> !suite.isTLS13());
    }

    public static Collection<VersionProbe13Random> getDefaultProbes(IOrchestrator orchestrator) {
        return Arrays.asList(
                new VersionProbe13Random(orchestrator, ProtocolVersion.SSL2),
                new VersionProbe13Random(orchestrator, ProtocolVersion.SSL3),
                new VersionProbe13Random(orchestrator, ProtocolVersion.TLS10),
                new VersionProbe13Random(orchestrator, ProtocolVersion.TLS11),
                new VersionProbe13Random(orchestrator, ProtocolVersion.TLS12));
    }

    private final Random random = new Random();
    private final ProtocolVersion versionToTest;

    public VersionProbe13Random(IOrchestrator orchestrator, ProtocolVersion versionToTest) {
        super(orchestrator);
        this.versionToTest = versionToTest;
    }

    @Override
    protected String getHostnamePrefix() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.versionToTest.name());
        sb.append('.');
        sb.append(super.getHostnamePrefix());
        return sb.toString();
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return ProbeRequirements.TRUE()
                .needResultOfTypeMatching(
                        VersionProbe.class,
                        VersionProbeResult.class,
                        res -> res.supportsVersion(ProtocolVersion.TLS13, false),
                        "Client does not support TLS 1.3")
                .needResultOfTypeMatching(
                        VersionProbe.class,
                        VersionProbeResult.class,
                        res -> res.supportsVersion(versionToTest, false),
                        "Client does not support " + versionToTest
                                + " - will not test downgrade protection against it");
    }

    @Override
    public ParametrizedClientProbeResult<ProtocolVersion, VersionProbe13RandomResult> execute(State state,
            DispatchInformation dispatchInformation) throws DispatchException {
        LOGGER.debug("Testing version {}", versionToTest);
        Config config = state.getConfig();
        WorkflowTrace trace = state.getWorkflowTrace();
        config.setHighestProtocolVersion(versionToTest);
        config.setDefaultSelectedProtocolVersion(versionToTest);
        config.setDefaultApplicationMessageData("TLS Version: " + versionToTest + "\n");
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        byte[] serverRandomPostfix;
        if (versionToTest == ProtocolVersion.TLS12) {
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
        extendWorkflowTraceToApplication(trace, config);
        ClientAdapterResult cres = executeState(state, dispatchInformation);
        boolean res = state.getTlsContext().getSelectedProtocolVersion() == versionToTest;
        res = res && !state.getWorkflowTrace().executedAsPlanned(); // trace should be rejected
        if (cres != null) {
            res = res && !cres.contentShown.wasShown();
        }
        return new ParametrizedClientProbeResult<>(getClass(), versionToTest, new VersionProbe13RandomResult(res));
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class VersionProbe13RandomResult implements Serializable {
        public final boolean downgradeProtectionImplemented;

        public VersionProbe13RandomResult(boolean downgradeProtectionImplemented) {
            this.downgradeProtectionImplemented = downgradeProtectionImplemented;
        }

    }

}
