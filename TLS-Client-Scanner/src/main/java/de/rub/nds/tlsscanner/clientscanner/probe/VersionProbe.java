package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class VersionProbe extends BaseStatefulProbe<Map<ProtocolVersion, State>> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionProbe() {
        this.defaultState = new HashMap<>();
    }

    @Override
    protected Pair<ClientProbeResult, Map<ProtocolVersion, State>> execute(State state,
            DispatchInformation dispatchInformation, Map<ProtocolVersion, State> previousState) {
        ProtocolVersion toTest = null;
        for (ProtocolVersion v : ProtocolVersion.values()) {
            if (!previousState.containsKey(v)) {
                toTest = v;
                break;
            }
        }
        if (toTest == null) {
            throw new RuntimeException("No version left to test");
        }
        LOGGER.debug("Testing version {}", toTest);
        Config config = state.getConfig();
        config.setHighestProtocolVersion(toTest);
        config.setDefaultSelectedProtocolVersion(toTest);
        config.setEnforceSettings(true);
        config.setDefaultApplicationMessageData("TLS Version: " + toTest);
        config.setHttpsParsingEnabled(true);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace https_trace = factory.createWorkflowTrace(WorkflowTraceType.HTTPS, RunningModeType.SERVER);
        TlsAction traceRecvCHLO = https_trace.removeTlsAction(0);
        if (!(traceRecvCHLO instanceof ReceiveAction
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().size() == 1
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().get(0) instanceof ClientHelloMessage)) {
            throw new RuntimeException("Unknown first action in handshake");
        }
        state.getWorkflowTrace().addTlsActions(https_trace.getTlsActions());
        executeState(state);
        previousState.put(toTest, state);
        return Pair.of(null, previousState);
    }

}