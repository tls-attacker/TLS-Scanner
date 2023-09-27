/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public abstract class SessionTicketBaseProbe<Result extends ProbeResult<ServerReport>>
        extends TlsProbe<ServerReport, Result> {
    protected List<ProtocolVersion> versionsToTest;

    /**
     * Taken from report (in {@link #adjustConfig(ServerReport)}). Used to configure initial
     * handshake (in {@link #configureInitialHandshake(ProtocolVersion)})
     */
    protected List<CipherSuite> supportedSuites;

    protected ScannerConfig scannerConfig;

    protected SessionTicketBaseProbe(
            ParallelExecutor parallelExecutor, TlsProbeType type, ScannerConfig scannerConfig) {
        super(parallelExecutor, type);
        this.scannerConfig = scannerConfig;
        versionsToTest =
                Arrays.asList(
                        ProtocolVersion.TLS10,
                        ProtocolVersion.TLS11,
                        ProtocolVersion.TLS12,
                        ProtocolVersion.TLS13);
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.getCipherSuites() != null
                && !report.getCipherSuites().isEmpty()
                && report.getVersions() != null
                && !report.getVersions().isEmpty();
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = new ArrayList<>(report.getCipherSuites());
        versionsToTest =
                versionsToTest.stream()
                        .filter(version -> report.getVersions().contains(version))
                        .collect(Collectors.toList());
    }

    protected ResponseFingerprint extractFingerprint(State state) {
        return ResponseExtractor.getFingerprint(
                state, state.getWorkflowTrace().getFirstReceivingAction());
    }

    protected Config configureInitialHandshake(ProtocolVersion version) {
        Config tlsConfig = scannerConfig.createConfig();

        List<CipherSuite> ciphersuites =
                supportedSuites.stream()
                        .filter(suite -> suite.isSupportedInProtocol(version))
                        .collect(Collectors.toList());
        boolean haveEcSuite =
                version.isTLS13()
                        || ciphersuites.stream().anyMatch(cs -> cs.name().contains("_EC"));

        List<NamedGroup> groups;
        if (version == ProtocolVersion.TLS13) {
            groups = new LinkedList<>();
            for (NamedGroup group : NamedGroup.getImplemented()) {
                if (group.isTls13()) {
                    groups.add(group);
                }
            }
        } else {
            groups = NamedGroup.getImplemented();
        }

        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        // versions, groups, suites
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.setSupportedVersions(version);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setDefaultClientKeyShareNamedGroups(groups);
        tlsConfig.setDefaultClientSupportedCipherSuites(ciphersuites);
        tlsConfig.setDefaultSelectedCipherSuite(
                tlsConfig.getDefaultClientSupportedCipherSuites().get(0));

        // extensions
        tlsConfig.setAddEllipticCurveExtension(haveEcSuite);
        tlsConfig.setAddSessionTicketTLSExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(false);
        tlsConfig.setAddExtendedMasterSecretExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        if (version.isTLS13()) {
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
        } else {
            tlsConfig.setAddECPointFormatExtension(haveEcSuite);
        }

        return tlsConfig;
    }

    protected State prepareInitialHandshake(ProtocolVersion version) {
        Config config = configureInitialHandshake(version);
        State state = new State(config);
        WorkflowTrace trace = state.getWorkflowTrace();

        if (!version.isTLS13()) {
            ReceiveAction ticketAction = new ReceiveAction("client", new NewSessionTicketMessage());
            ticketAction.addActionOption(ActionOption.MAY_FAIL);
            trace.addTlsAction(trace.getTlsActions().size() - 1, ticketAction);
        }
        // after Handshake is finished, we sent an application message to the server
        // since some servers (for example server using BoringSSL) only immediately issue session
        // tickets after an
        // application message is sent
        ((MessageAction) trace.getLastSendingAction())
                .getHttpMessages()
                .add(new HttpRequestMessage());
        if (!(trace.getLastAction() instanceof ReceiveAction)) {
            trace.addTlsAction(new ReceiveAction("client"));
        }
        ApplicationMessage app = new ApplicationMessage();
        app.setRequired(false);
        ((ReceiveAction) trace.getLastAction()).getExpectedMessages().add(app);

        return state;
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

        State state = new State(tlsConfig);

        // patch trace to allow new tickets
        ReceiveAction action = (ReceiveAction) state.getWorkflowTrace().getFirstReceivingAction();
        List<ProtocolMessage> messages = action.getExpectedMessages();
        ProtocolMessage newTicket = new NewSessionTicketMessage();
        newTicket.setRequired(false);
        messages.add(newTicket);
        action.setExpectedMessages(messages);

        return state;
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
