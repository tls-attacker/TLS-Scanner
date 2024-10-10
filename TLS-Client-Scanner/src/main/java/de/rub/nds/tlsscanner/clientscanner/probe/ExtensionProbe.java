package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

import java.util.ArrayList;
import java.util.List;

public class ExtensionProbe extends TlsClientProbe {

    private List<ExtensionType> allSupportedExtensions;
    private TestResult extendedMasterSecret = TestResults.FALSE;
    private TestResult encryptThenMac = TestResults.FALSE;
    private TestResult secureRenegotiation = TestResults.FALSE;
    private TestResult sessionTickets = TestResults.FALSE;
    private TestResult certStatusRequest = TestResults.FALSE;
    private TestResult certStatusRequestV2 = TestResults.FALSE;

    public ExtensionProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.EXTENSIONS, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION,
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
                TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2,
                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS);
    }

    @Override
    protected void executeTest() {
        allSupportedExtensions = new ArrayList<>();
        WorkflowTrace trace = new WorkflowConfigurationFactory(scannerConfig.createConfig()).createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
        trace.addTlsAction(new ReceiveTillAction(new ClientHelloMessage()));
        State state = new State(trace);
        executeState(state);
        HandshakeMessage clientHello = WorkflowTraceResultUtil.getLastReceivedMessage(state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO);
        if (clientHello == null) {
            LOGGER.debug(
                    "Did not receive a ClientHello, something went wrong");
            return;
        }
        clientHello.getExtensions().forEach(extension -> allSupportedExtensions.add(extension.getExtensionTypeConstant()));
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ClientReport report) {}

    @Override
    protected void mergeData(ClientReport report) {

    }
}
