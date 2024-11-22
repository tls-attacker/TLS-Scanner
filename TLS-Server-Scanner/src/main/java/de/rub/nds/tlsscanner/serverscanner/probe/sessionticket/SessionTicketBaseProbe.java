/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.StaticReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.StaticSendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
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
    private static final Requirement<ServerReport> REQ_SUPPORTS_SESSION_TICKET_EXTENSION =
            new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION);
    private static final Requirement<ServerReport> REQ_ISSUES_TLS_13_TICKETS =
            new PropertyTrueRequirement<ServerReport>(
                            TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE)
                    .or(
                            new PropertyTrueRequirement<>(
                                    TlsAnalyzedProperty
                                            .ISSUES_TLS13_SESSION_TICKETS_WITH_APPLICATION_DATA));

    protected static final Requirement<ServerReport> REQ_SUPPORTS_RESUMPTION_TICKET_EXT =
            new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION);
    protected static final Requirement<ServerReport> REQ_SUPPORTS_RESUMPTION_TLS_13 =
            new PropertyTrueRequirement<ServerReport>(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE)
                    .or(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK));
    protected static final Requirement<ServerReport> REQ_SUPPORTS_RESUMPTION =
            REQ_SUPPORTS_RESUMPTION_TICKET_EXT.or(REQ_SUPPORTS_RESUMPTION_TLS_13);

    protected List<ProtocolVersion> versionsToTest;

    /**
     * Taken from report (in {@link #adjustConfig(ServerReport)}). Used to configure initial
     * handshake (in {@link #configureInitialHandshake(ProtocolVersion)})
     */
    protected List<CipherSuite> supportedSuites;

    private boolean issuesTickets12;
    private boolean issuesTickets13;

    private boolean resumesTickets12;
    private boolean resumesTickets13;

    protected SessionTicketBaseProbe(
            ParallelExecutor parallelExecutor, ConfigSelector configSelector, TlsProbeType type) {
        super(parallelExecutor, type, configSelector);
        versionsToTest =
                Arrays.asList(
                        ProtocolVersion.TLS10,
                        ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12,
                        ProtocolVersion.TLS13);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(
                        TlsProbeType.CIPHER_SUITE,
                        TlsProbeType.PROTOCOL_VERSION,
                        TlsProbeType.RESUMPTION)
                .and(REQ_SUPPORTS_SESSION_TICKET_EXTENSION.or(REQ_ISSUES_TLS_13_TICKETS));
    }

    protected boolean issuesTickets(ProtocolVersion version) {
        if (version.isTLS13()) {
            return issuesTickets13;
        } else {
            return issuesTickets12;
        }
    }

    protected boolean resumesTickets(ProtocolVersion version) {
        if (version.isTLS13()) {
            return resumesTickets13;
        } else {
            return resumesTickets12;
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = new ArrayList<>(report.getSupportedCipherSuites());
        versionsToTest =
                versionsToTest.stream()
                        .filter(version -> report.getSupportedProtocolVersions().contains(version))
                        .collect(Collectors.toList());

        if (!configSelector
                .getScannerConfig()
                .getExecutorConfig()
                .getScanDetail()
                .isGreaterEqualTo(ScannerDetail.ALL)) {
            // only keep 1.3 and highest pre 1.3 version
            // we sort the versions descending (without 1.3)
            // and remove all but the first from the versions to test
            List<ProtocolVersion> sortedVersions = new ArrayList<>(versionsToTest);
            sortedVersions.remove(ProtocolVersion.TLS13);
            if (!sortedVersions.isEmpty()) {
                ProtocolVersion.sort(sortedVersions, false);
                sortedVersions.remove(0);
                versionsToTest.removeAll(sortedVersions);
            }
        }

        // use properties as approximation
        issuesTickets12 = REQ_SUPPORTS_SESSION_TICKET_EXTENSION.evaluate(report);
        issuesTickets13 = REQ_ISSUES_TLS_13_TICKETS.evaluate(report);
        resumesTickets12 = REQ_SUPPORTS_RESUMPTION_TICKET_EXT.evaluate(report);
        resumesTickets13 = REQ_SUPPORTS_RESUMPTION_TLS_13.evaluate(report);
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
            // in TLS 1.3 we also want to send application data as tickets might be issued
            // later
            // (e.g. BoringSSL sends the ticket just before sending the first application
            // data)
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
            tlsConfig.setDefaultLayerConfiguration(StackConfiguration.HTTPS);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
        } else {
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            tlsConfig.setDefaultLayerConfiguration(StackConfiguration.TLS);
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
        for (TlsAction action : trace.getTlsActions()) {
            if (action instanceof StaticReceivingAction) {
                for (ProtocolMessage message :
                        ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class)) {
                    if (message.getProtocolMessageType() == firstMessageFailing) {
                        patchTraceMightFailAfterIndex(trace, trace.getTlsActions().indexOf(action));
                        return;
                    }
                }
            }
            if (action instanceof StaticSendingAction) {
                for (ProtocolMessage message :
                        ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class)) {
                    if (message.getProtocolMessageType() == firstMessageFailing) {
                        patchTraceMightFailAfterIndex(trace, trace.getTlsActions().indexOf(action));
                        return;
                    }
                }
            }
        }
    }

    protected void patchTraceMightFailAfterIndex(WorkflowTrace trace, int index) {
        for (int i = index; i < trace.getTlsActions().size(); i++) {
            trace.getTlsActions().get(i).addActionOption(ActionOption.MAY_FAIL);
        }
    }

    protected void patchTraceMightFailAfterMessage(
            WorkflowTrace trace, HandshakeMessageType firstMessageFailing) {
        for (TlsAction action : trace.getTlsActions()) {
            if (action instanceof StaticReceivingAction) {
                for (ProtocolMessage message :
                        ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class)) {
                    if (message instanceof HandshakeMessage
                            && ((HandshakeMessage) message).getHandshakeMessageType()
                                    == firstMessageFailing) {
                        patchTraceMightFailAfterIndex(trace, trace.getTlsActions().indexOf(action));
                        return;
                    }
                }
            }
            if (action instanceof StaticSendingAction) {
                for (ProtocolMessage message :
                        ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class)) {
                    if (message instanceof HandshakeMessage
                            && ((HandshakeMessage) message).getHandshakeMessageType()
                                    == firstMessageFailing) {
                        patchTraceMightFailAfterIndex(trace, trace.getTlsActions().indexOf(action));
                        return;
                    }
                }
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
        return WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED)
                && WorkflowTraceResultUtil.didReceiveMessage(
                        trace, HandshakeMessageType.NEW_SESSION_TICKET)
                && ticketIssued;
    }

    protected boolean resumptionHandshakeSuccessful(State state, boolean checkAcceptedEarlyData) {
        WorkflowTrace trace = state.getWorkflowTrace();
        HandshakeMessage serverHello =
                WorkflowTraceResultUtil.getFirstReceivedMessage(
                        trace, HandshakeMessageType.SERVER_HELLO);
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
            if (WorkflowTraceResultUtil.getFirstReceivedMessage(
                                    trace, HandshakeMessageType.ENCRYPTED_EXTENSIONS)
                            .getExtension(EarlyDataExtensionMessage.class)
                    == null) {
                return false;
            }
        }

        // if server authenticated again (using cert), they rejected the ticket
        // if FIN was not received, either the server behaved wrong or we had the wrong
        // secret
        return !WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.CERTIFICATE)
                && WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED);
    }
}
