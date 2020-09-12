package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.MapUtil;

public class VersionProbe extends BaseStatefulProbe<VersionProbe.VersionProbeState> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Collection<ProtocolVersion> versionsToTest;

    public VersionProbe(IOrchestrator orchestrator, Collection<ProtocolVersion> versionsToTest) {
        super(orchestrator);
        this.versionsToTest = versionsToTest;
    }

    @Override
    protected VersionProbeState getDefaultState(DispatchInformation dispatchInformation) {
        return new VersionProbeState(versionsToTest);
    }

    public VersionProbe(IOrchestrator orchestrator) {
        this(orchestrator, Arrays.asList(ProtocolVersion.values()));
    }

    @Override
    protected VersionProbeState execute(State state,
            DispatchInformation dispatchInformation, VersionProbeState internalState) {
        ProtocolVersion toTest = internalState.getNext();
        LOGGER.debug("Testing version {}", toTest);
        Config config = state.getConfig();
        config.setHighestProtocolVersion(toTest);
        config.setDefaultSelectedProtocolVersion(toTest);
        config.setEnforceSettings(true);
        config.setDefaultApplicationMessageData("TLS Version: " + toTest);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        internalState.addResult(toTest, state);
        return internalState;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return null;
    }

    public static class VersionProbeState implements BaseStatefulProbe.InternalProbeState {
        private final Map<ProtocolVersion, State> states;
        private final List<ProtocolVersion> leftToTest;

        public VersionProbeState(Collection<ProtocolVersion> toTest) {
            states = new HashMap<>();
            leftToTest = new LinkedList<>(toTest);
        }

        public boolean hasChecked(ProtocolVersion v) {
            return states.containsKey(v);
        }

        public ProtocolVersion getNext() {
            return leftToTest.remove(0);
        }

        public void addResult(ProtocolVersion v, State state) {
            states.put(v, state);
        }

        @Override
        public VersionProbeResult getResult() {
            return new VersionProbeResult(states);
        }

        @Override
        public boolean isDone() {
            return leftToTest.isEmpty();
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class VersionProbeResult extends ClientProbeResult {
        private final Map<ProtocolVersion, Boolean> versionSupport;

        public VersionProbeResult(Map<ProtocolVersion, State> states) {
            versionSupport = new HashMap<>();
            for (Map.Entry<ProtocolVersion, State> kv : states.entrySet()) {
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
        public void merge(ClientReport report) {
            // TODO synchronization?
            if (report.hasResult(VersionProbe.class)) {
                // merge
                VersionProbeResult other = (VersionProbeResult) report.getResult(VersionProbe.class);
                Map<ProtocolVersion, Boolean> m = other.versionSupport;
                MapUtil.mergeIntoFirst(m, versionSupport);
                report.markAsChangedAndNotify();
            } else {
                report.putResult(VersionProbe.class, this);
            }
        }
    }

}