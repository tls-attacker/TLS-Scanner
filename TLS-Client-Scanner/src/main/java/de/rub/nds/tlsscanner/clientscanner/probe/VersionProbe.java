package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionProbe extends BaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final List<CipherSuite> suites13;
    private static final List<CipherSuite> suitesPre13;
    static {
        suitesPre13 = CipherSuite.getImplemented();
        suitesPre13.removeIf((suite) -> suite.isTLS13());
        suites13 = CipherSuite.getImplemented();
        suites13.removeIf((suite) -> !suite.isTLS13());
    }

    public static Collection<VersionProbe> getDefaultProbes(IOrchestrator orchestrator) {
        return Arrays.asList(
                new VersionProbe(orchestrator, ProtocolVersion.SSL2),
                new VersionProbe(orchestrator, ProtocolVersion.SSL3),
                new VersionProbe(orchestrator, ProtocolVersion.TLS10),
                new VersionProbe(orchestrator, ProtocolVersion.TLS11),
                new VersionProbe(orchestrator, ProtocolVersion.TLS12),
                new VersionProbe(orchestrator, ProtocolVersion.TLS13));
    }

    private final ProtocolVersion versionToTest;

    public VersionProbe(IOrchestrator orchestrator, ProtocolVersion versionToTest) {
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
        return null;
    }

    @Override
    public ParametrizedClientProbeResult<ProtocolVersion, Boolean> execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        LOGGER.debug("Testing version {}", versionToTest);
        Config config = state.getConfig();
        config.setHighestProtocolVersion(versionToTest);
        config.setDefaultSelectedProtocolVersion(versionToTest);
        config.setDefaultApplicationMessageData("TLS Version: " + versionToTest);
        if (versionToTest == ProtocolVersion.TLS13) {
            // cf TLS-Attacker/resources/configs/tls13.config
            config.setDefaultServerSupportedCiphersuites(suites13);
            config.setAddECPointFormatExtension(false);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddSupportedVersionsExtension(true);
            config.setAddKeyShareExtension(true);

            config.setAddRenegotiationInfoExtension(false);
            // config.setDefaultServerSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA256);
        }
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        ClientAdapterResult cres = executeState(state, dispatchInformation);
        // TODO use cres to evaluate further
        boolean res = state.getTlsContext().getSelectedProtocolVersion() == versionToTest && state.getWorkflowTrace().executedAsPlanned();
        return new ParametrizedClientProbeResult<>(getClass(), versionToTest, res);
    }

}
