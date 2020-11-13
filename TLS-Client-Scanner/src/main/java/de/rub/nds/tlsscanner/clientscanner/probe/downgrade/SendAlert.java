/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.downgrade;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.MapUtil;

public class SendAlert extends BaseStatefulProbe<SendAlert.AlertDowngradeInternalState> {
    private final AlertLevel alertLevel;
    private final AlertDescription alertDesc;

    public static Collection<SendAlert> getDefaultProbes(Orchestrator orchestrator) {
        return Arrays.asList(
                new SendAlert(orchestrator, AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY),
                new SendAlert(orchestrator, AlertLevel.WARNING, AlertDescription.UNEXPECTED_MESSAGE),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.ACCESS_DENIED),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.DECODE_ERROR),
                new SendAlert(orchestrator, AlertLevel.WARNING, AlertDescription.PROTOCOL_VERSION),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR),
                new SendAlert(orchestrator, AlertLevel.WARNING, AlertDescription.INAPPROPRIATE_FALLBACK),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.INAPPROPRIATE_FALLBACK),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.UNRECOGNIZED_NAME),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.MISSING_EXTENSION),
                new SendAlert(orchestrator, AlertLevel.FATAL, AlertDescription.NO_APPLICATION_PROTOCOL));
    }

    public static Collection<SendAlert> getAllProbes(Orchestrator orchestrator) {
        List<SendAlert> ret = new ArrayList<>(AlertLevel.values().length * AlertDescription.values().length);
        for (AlertDescription desc : AlertDescription.values()) {
            for (AlertLevel level : AlertLevel.values()) {
                ret.add(new SendAlert(orchestrator, level, desc));
            }
        }
        return ret;
    }

    public SendAlert(Orchestrator orchestrator, AlertLevel alertLevel, AlertDescription alertDesc) {
        super(orchestrator);
        this.alertLevel = alertLevel;
        this.alertDesc = alertDesc;
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return null;
    }

    @Override
    protected AlertDowngradeInternalState getDefaultState() {
        return new AlertDowngradeInternalState(getClass(), alertLevel, alertDesc);
    }

    @Override
    protected String getHostnamePrefix(AlertDowngradeInternalState internalState) {
        StringBuilder sb = new StringBuilder();
        sb.append(this.alertLevel.name());
        sb.append('.');
        sb.append(this.alertDesc.name());
        sb.append('.');
        sb.append(super.getHostnamePrefix(internalState));
        return sb.toString();
    }

    @Override
    protected AlertDowngradeInternalState execute(State state, DispatchInformation dispatchInformation,
            AlertDowngradeInternalState internalState) throws DispatchException {
        // only analyze chlo
        if (!internalState.isFirstDone()) {
            WorkflowTrace trace = state.getWorkflowTrace();
            AlertMessage alertMsg = new AlertMessage();
            alertMsg.setConfig(alertLevel, alertDesc);
            trace.addTlsAction(new SendAction(alertMsg));
        }
        internalState.putCHLO(dispatchInformation.chlo);
        executeState(state, dispatchInformation);
        return internalState;
    }

    public static class AlertDowngradeInternalState extends DowngradeInternalState {
        private final AlertLevel alertLevel;
        private final AlertDescription alertDesc;

        public AlertDowngradeInternalState(Class<? extends Probe> clazz, AlertLevel alertLevel,
                AlertDescription alertDesc) {
            super(clazz);
            this.alertLevel = alertLevel;
            this.alertDesc = alertDesc;
        }

        @Override
        public AlertDowngradeResult toResult() {
            return new AlertDowngradeResult(clazz, firstCHLO, secondCHLO, alertLevel, alertDesc);
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class RfcAlert implements Serializable {
        public final AlertLevel level;
        public final AlertDescription description;

        public RfcAlert(AlertLevel level, AlertDescription description) {
            this.level = level;
            this.description = description;
        }
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class AlertDowngradeResult extends ClientProbeResult {
        private final Map<RfcAlert, DowngradeResult> resultMap;

        public AlertDowngradeResult(Class<? extends Probe> clazz, ClientHelloMessage chlo1, ClientHelloMessage chlo2,
                AlertLevel alertLevel, AlertDescription alertDesc) {
            resultMap = new HashMap<>();
            resultMap.put(new RfcAlert(alertLevel, alertDesc), new DowngradeResult(clazz, chlo1, chlo2));
        }

        @Override
        @SuppressWarnings("squid:S2445")
        // sonarlint: Blocks should be synchronized on "private final" fields
        public void merge(ClientReport report) {
            synchronized (report) {
                if (report.hasResult(SendAlert.class)) {
                    // merge
                    AlertDowngradeResult other = report.getResult(SendAlert.class, AlertDowngradeResult.class);
                    MapUtil.mergeIntoFirst(other.resultMap, resultMap);
                    report.markAsChangedAndNotify();
                } else {
                    report.putResult(SendAlert.class, this);
                }
            }
        }
    }
}
