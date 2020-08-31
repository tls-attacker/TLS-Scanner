package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class VersionProbe extends BaseStatefulProbe<Map<ProtocolVersion, State>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Iterable<ProtocolVersion> versionsToTest;

    public VersionProbe(IOrchestrator orchestrator, Iterable<ProtocolVersion> versionsToTest) {
        super(orchestrator);
        this.defaultState = new HashMap<>();
        this.versionsToTest = versionsToTest;
    }

    public VersionProbe(IOrchestrator orchestrator) {
        this(orchestrator, Arrays.asList(ProtocolVersion.values()));
    }

    @Override
    protected Pair<ClientProbeResult, Map<ProtocolVersion, State>> execute(State state,
            DispatchInformation dispatchInformation, Map<ProtocolVersion, State> previousState) {
        ProtocolVersion toTest = null;
        boolean last = false;
        for (Iterator<ProtocolVersion> it = versionsToTest.iterator(); it.hasNext();) {
            ProtocolVersion v = it.next();
            if (!previousState.containsKey(v)) {
                toTest = v;
                last = !it.hasNext();
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
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace https_trace = factory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        TlsAction traceRecvCHLO = https_trace.removeTlsAction(0);
        if (!(traceRecvCHLO instanceof ReceiveAction
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().size() == 1
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().get(0) instanceof ClientHelloMessage)) {
            throw new RuntimeException("Unknown first action in handshake");
        }
        state.getWorkflowTrace().addTlsActions(https_trace.getTlsActions());
        executeState(state);
        previousState.put(toTest, state);
        VersionProbeResult ret = null;
        if (last) {
            ret = new VersionProbeResult(previousState);
        }
        return Pair.of(ret, previousState);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult() {
        return null;
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class VersionProbeResult extends ClientProbeResult {
        private final Map<ProtocolVersion, Boolean> versionSupport;

        public VersionProbeResult(Map<ProtocolVersion, State> state) {
            versionSupport = new HashMap<>();
            for (Map.Entry<ProtocolVersion, State> kv : state.entrySet()) {
                versionSupport.put(kv.getKey(), checkSupported(kv.getKey(), kv.getValue()));
            }
        }

        private Boolean checkSupported(ProtocolVersion v, State s) {
            boolean foundSHLO = false;
            for (TlsAction a : s.getWorkflowTrace().getTlsActions()) {
                if (!foundSHLO && a instanceof SendAction) {
                    for (ProtocolMessage m : ((SendAction) a).getMessages()) {
                        if (m instanceof ServerHelloMessage) {
                            foundSHLO = true;
                            break;
                        }
                    }
                } else if (foundSHLO && a instanceof ReceiveAction) {
                    // client's response to our SHLO
                    // TODO maybe do a deeper check here...
                    return a.executedAsPlanned();
                }
            }
            throw new RuntimeException(String.format("Could not determine whether version %s is supported", v));
        }

        @Override
        public String getProbeName() {
            return "VersionProbe";
        }

        @Override
        public void merge(ClientReport report) {
            // TODO synchronization?
            if (report.hasResult(VersionProbe.class)) {
                // merge
                VersionProbeResult other = (VersionProbeResult) report.getResult(VersionProbe.class);
                Map<ProtocolVersion, Boolean> m = other.versionSupport;
                for (Map.Entry<ProtocolVersion, Boolean> kv : versionSupport.entrySet()) {
                    if (m.containsKey(kv.getKey()) && m.get(kv.getKey()) != null
                            && !m.get(kv.getKey()).equals(kv.getValue())) {
                        throw new IllegalStateException("Cannot merge contradictory information");
                    } else {
                        m.put(kv.getKey(), kv.getValue());
                    }
                }
            } else {
                report.putResult(VersionProbe.class, this);
            }
        }
    }

}