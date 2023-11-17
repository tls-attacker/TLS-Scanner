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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret.Secret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketHolder;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls12;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls13;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SessionTicketUtil {
    private SessionTicketUtil() {}

    /**
     * generates a list of all session secrets of current state which might be included in a session
     * ticket by the server
     *
     * @param state
     * @return
     */
    public static List<PossibleSecret> generateSecretList(State state) {
        List<PossibleSecret> secretList = new LinkedList<>();
        TlsContext context = state.getTlsContext();
        if (state.getTlsContext().getSelectedProtocolVersion().isTLS13()) {
            secretList.add(
                    new PossibleSecret(Secret.HANDSHAKE_SECRET, context.getHandshakeSecret()));
            secretList.add(new PossibleSecret(Secret.MASTER_SECRET, context.getMasterSecret()));
            secretList.add(
                    new PossibleSecret(
                            Secret.RESUMPTION_SECRET, context.getResumptionMasterSecret()));
            if (context.getPskSets() != null) {
                secretList.addAll(
                        context.getPskSets().stream()
                                .map(
                                        pskset ->
                                                new PossibleSecret(
                                                        Secret.PRESHARED_KEY,
                                                        pskset.getPreSharedKey()))
                                .collect(Collectors.toList()));
            }
        } else {
            secretList.add(
                    new PossibleSecret(Secret.PREMASTER_SECRET, context.getPreMasterSecret()));
            secretList.add(new PossibleSecret(Secret.MASTER_SECRET, context.getMasterSecret()));
        }
        return secretList;
    }

    public static TicketHolder getSessionTickets(State state) {
        if (state.getTlsContext() == null
                || state.getTlsContext().getSelectedProtocolVersion() == null) {
            return new TicketHolder(null);
        }
        List<PossibleSecret> possibleSecrets = generateSecretList(state);
        TlsContext context = state.getTlsContext();
        ProtocolVersion protocolVersion = context.getSelectedProtocolVersion();
        if (protocolVersion.isTLS13()) {
            if (context.getPskSets() == null){
                return new TicketHolder(protocolVersion);
            }
            return context.getPskSets().stream()
                    .map(pskset -> new TicketTls13(pskset, possibleSecrets))
                    .collect(TicketHolder.collector(protocolVersion));
        } else {
            if (context.getLatestSessionTicket() == null) {
                return new TicketHolder(protocolVersion);
            }
            return new TicketHolder(
                    protocolVersion,
                    new TicketTls12(
                            context.getLatestSessionTicket(),
                            context.getMasterSecret(),
                            possibleSecrets));
        }
    }
}
