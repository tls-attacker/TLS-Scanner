/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsServerProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public abstract class SessionTicketBaseProbe extends TlsServerProbe {
    protected List<ProtocolVersion> versionsToTest;

    /**
     * Taken from report (in {@link #adjustConfig(ServerReport)}). Used to configure initial
     * handshake (in {@link #configureInitialHandshake(ProtocolVersion)})
     */
    protected List<CipherSuite> supportedSuites;

    protected SessionTicketBaseProbe(
            ParallelExecutor parallelExecutor, ConfigSelector configSelector, TlsProbeType type) {
        super(parallelExecutor, type, configSelector);
        versionsToTest =
                Arrays.asList(
                        ProtocolVersion.TLS10,
                        ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12,
                        ProtocolVersion.TLS13);
        versionsToTest = Arrays.asList(ProtocolVersion.TLS12, ProtocolVersion.TLS13);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE, TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = new ArrayList<>(report.getSupportedCipherSuites());
        versionsToTest =
                versionsToTest.stream()
                        .filter(version -> report.getSupportedProtocolVersions().contains(version))
                        .collect(Collectors.toList());
    }

    protected ResponseFingerprint extractFingerprint(State state) {
        return ResponseExtractor.getFingerprint(
                state, state.getWorkflowTrace().getFirstReceivingAction());
    }

    protected Config configureInitialHandshake(ProtocolVersion version) {
        Config tlsConfig;
        if (version.isTLS13()) {
            tlsConfig = configSelector.getTls13BaseConfig();
        } else {
            tlsConfig = configSelector.getBaseConfig();
        }

        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.setSupportedVersions(version);
        if (version.isTLS13()) {
            // in TLS 1.3 we also want to send application data as tickets might be issued later
            // (e.g. BoringSSL sends the ticket just before sending the first application data)
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
            tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
        } else {
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.TLS);
        }
        tlsConfig.setAddSessionTicketTLSExtension(true);

        configSelector.repairConfig(tlsConfig);
        return tlsConfig;
    }

    protected State prepareInitialHandshake(ProtocolVersion version) {
        Config config = configureInitialHandshake(version);
        return new State(config);
    }

    protected State prepareResumptionHandshake(
            ProtocolVersion resumeVersion, Ticket ticketToUse, boolean earlyData) {
        if (!resumeVersion.isTLS13() && earlyData) {
            throw new IllegalArgumentException("Early Data only supported in TLS 1.3");
        }

        Config tlsConfig = configureInitialHandshake(resumeVersion);
        tlsConfig.setAddEarlyDataExtension(earlyData);

        if (resumeVersion.isTLS13()) {
            if (earlyData) {
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.ZERO_RTT);
            } else {
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.TLS13_PSK);
            }
        } else {
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.RESUMPTION);
        }

        ticketToUse.applyTo(tlsConfig);

        return new State(tlsConfig);
    }

    protected void patchTraceMightFailAfterMessage(
            WorkflowTrace trace, ProtocolMessageType firstMessageFailing) {
        TlsAction firstActionWithMsg =
                WorkflowTraceUtil.getFirstActionForMessage(firstMessageFailing, trace);
        patchTraceMightFailAfterAction(trace, firstActionWithMsg);
    }

    protected void patchTraceMightFailAfterMessage(
            WorkflowTrace trace, HandshakeMessageType firstMessageFailing) {
        TlsAction firstActionWithMsg =
                WorkflowTraceUtil.getFirstActionForMessage(firstMessageFailing, trace);
        patchTraceMightFailAfterAction(trace, firstActionWithMsg);
    }

    protected void patchTraceMightFailAfterAction(
            WorkflowTrace trace, TlsAction firstFailingAction) {
        boolean foundAction = false;
        for (TlsAction action : trace.getTlsActions()) {
            if (action == firstFailingAction) {
                foundAction = true;
            }
            if (foundAction) {
                action.addActionOption(ActionOption.MAY_FAIL);
            }
        }
    }

    protected FingerPrintTask prepareResumptionFingerprintTask(
            ProtocolVersion resumeVersion, Ticket ticketToUse, boolean earlyData) {
        State state = prepareResumptionHandshake(resumeVersion, ticketToUse, earlyData);
        state.getConfig().setWorkflowExecutorShouldClose(false);
        return new FingerPrintTask(state, getParallelExecutor().getReexecutions());
    }

    protected FingerPrintTask prepareResumptionFingerprintTask(
            ProtocolVersion resumeVersion, ModifiedTicket ticketToUse, boolean earlyData) {
        return prepareResumptionFingerprintTask(
                resumeVersion, ticketToUse.getResultingTicket(), earlyData);
    }

    protected FingerPrintTask prepareResumptionFingerprintTask(
            ProtocolVersion resumeVersion,
            ModifiedTicket ticketToUse,
            boolean earlyData,
            ProtocolMessageType firstMessageFailing) {
        FingerPrintTask task =
                prepareResumptionFingerprintTask(
                        resumeVersion, ticketToUse.getResultingTicket(), earlyData);
        patchTraceMightFailAfterMessage(task.getState().getWorkflowTrace(), firstMessageFailing);
        return task;
    }

    protected FingerPrintTask prepareResumptionFingerprintTask(
            ProtocolVersion resumeVersion,
            ModifiedTicket ticketToUse,
            boolean earlyData,
            HandshakeMessageType firstMessageFailing) {
        FingerPrintTask task =
                prepareResumptionFingerprintTask(
                        resumeVersion, ticketToUse.getResultingTicket(), earlyData);
        patchTraceMightFailAfterMessage(task.getState().getWorkflowTrace(), firstMessageFailing);
        return task;
    }

    protected boolean initialHandshakeSuccessful(State state) {
        // TODO reduce complexity - optimally should just be trace.executedAsPlanned
        boolean ticketIssued;
        TlsContext context = state.getTlsContext();
        if (state.getTlsContext() == null
                || state.getTlsContext().getSelectedProtocolVersion() == null) {
            return false;
        }

        if (state.getTlsContext().getSelectedProtocolVersion().isTLS13()) {
            ticketIssued =
                    context.getPskSets() != null
                            && context.getPskSets().stream()
                                    .anyMatch(
                                            pskSet -> pskSet.getPreSharedKeyIdentity().length > 0);
        } else {
            ticketIssued =
                    context.getSessionList().stream()
                            .anyMatch(
                                    session ->
                                            session instanceof TicketSession
                                                    && ((TicketSession) session).getTicket().length
                                                            > 0);
        }

        WorkflowTrace trace = state.getWorkflowTrace();
        return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)
                && WorkflowTraceUtil.didReceiveMessage(
                        HandshakeMessageType.NEW_SESSION_TICKET, trace)
                && ticketIssued;
    }

    protected boolean resumptionHandshakeSuccessful(State state, boolean checkAcceptedEarlyData) {
        // TODO reduce complexity - optimally should just be trace.executedAsPlanned
        WorkflowTrace trace = state.getWorkflowTrace();
        HandshakeMessage serverHello =
                WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace);
        if (state.getTlsContext() == null
                || state.getTlsContext().getSelectedProtocolVersion() == null
                || serverHello == null) {
            return false;
        }

        if (state.getTlsContext().getSelectedProtocolVersion().isTLS13()
                && serverHello.getExtension(PreSharedKeyExtensionMessage.class) == null) {
            // in TLS 1.3 we require the PSK extension
            return false;
        }
        if (checkAcceptedEarlyData) {
            if (!state.getTlsContext().getSelectedProtocolVersion().isTLS13()) {
                return false;
            }
            if (WorkflowTraceUtil.getFirstReceivedMessage(
                                    HandshakeMessageType.ENCRYPTED_EXTENSIONS, trace)
                            .getExtension(EarlyDataExtensionMessage.class)
                    == null) {
                return false;
            }
        }

        // if server authenticated again (using cert), they rejected the ticket
        // if FIN was not received, either the server behaved wrong or we had the wrong secret
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE, trace)
                && WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace);
    }
}
