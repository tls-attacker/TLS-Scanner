/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret.Secret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketHolder;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls12;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls13;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SessionTicketUtil {
    private SessionTicketUtil() {}

    private static void addSecretIfNotNull(
            List<SessionSecret> secretList, Secret secretType, byte[] secret) {
        if (secret != null) {
            secretList.add(new SessionSecret(secretType, secret));
        }
    }

    /**
     * generates a list of all session secrets of current state which might be included in a session
     * ticket by the server
     *
     * @param state The state to extract the secrets from.
     * @return List of secrets associated with the state.
     */
    public static List<SessionSecret> generateSecretList(State state) {
        List<SessionSecret> secretList = new LinkedList<>();
        TlsContext context = state.getTlsContext();
        if (state.getTlsContext().getSelectedProtocolVersion().isTLS13()) {
            addSecretIfNotNull(secretList, Secret.HANDSHAKE_SECRET, context.getHandshakeSecret());
            addSecretIfNotNull(secretList, Secret.MASTER_SECRET, context.getMasterSecret());
            addSecretIfNotNull(
                    secretList, Secret.RESUMPTION_SECRET, context.getResumptionMasterSecret());
            if (context.getPskSets() != null) {
                for (byte[] secret :
                        context.getPskSets().stream()
                                .map(PskSet::getPreSharedKey)
                                .collect(Collectors.toList())) {
                    addSecretIfNotNull(secretList, Secret.PRESHARED_KEY, secret);
                }
            }
        } else {
            addSecretIfNotNull(secretList, Secret.PREMASTER_SECRET, context.getPreMasterSecret());
            addSecretIfNotNull(secretList, Secret.MASTER_SECRET, context.getMasterSecret());
        }
        return secretList;
    }

    public static TicketHolder getSessionTickets(State state) {
        if (state.getTlsContext() == null
                || state.getTlsContext().getSelectedProtocolVersion() == null) {
            return new TicketHolder(null);
        }
        TlsContext context = state.getTlsContext();
        ProtocolVersion protocolVersion = context.getSelectedProtocolVersion();
        if (protocolVersion.isTLS13()) {
            if (context.getPskSets() == null) {
                return new TicketHolder(protocolVersion);
            }
            List<SessionSecret> sessionSecrets = generateSecretList(state);
            return context.getPskSets().stream()
                    .map(pskset -> new TicketTls13(pskset, sessionSecrets))
                    .collect(TicketHolder.collector(protocolVersion));
        } else {
            if (context.getLatestSessionTicket() == null) {
                return new TicketHolder(protocolVersion);
            }
            List<SessionSecret> sessionSecrets = generateSecretList(state);
            return new TicketHolder(
                    protocolVersion,
                    new TicketTls12(
                            context.getLatestSessionTicket(),
                            context.getMasterSecret(),
                            sessionSecrets));
        }
    }
}
