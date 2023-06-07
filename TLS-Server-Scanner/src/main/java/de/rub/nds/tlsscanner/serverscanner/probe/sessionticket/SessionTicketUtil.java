/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret.Secret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls12;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls13;

public class SessionTicketUtil {
    private SessionTicketUtil() {
    }

    /**
     * generates a list of all session secrets of current state which might be included in a session ticket by the
     * server
     *
     * @param  state
     * @return
     */
    public static List<PossibleSecret> generateSecretList(State state) {
        List<PossibleSecret> secretList = new LinkedList<>();
        TlsContext context = state.getTlsContext();
        if (state.getTlsContext().getSelectedProtocolVersion().isTLS13()) {
            secretList.add(new PossibleSecret(Secret.HANDSHAKE_SECRET, context.getHandshakeSecret()));
            secretList.add(new PossibleSecret(Secret.MASTER_SECRET, context.getMasterSecret()));
            secretList.add(new PossibleSecret(Secret.RESUMPTION_SECRET, context.getResumptionMasterSecret()));
            if (context.getPskSets() != null) {
                secretList.addAll(context.getPskSets().stream()
                    .map(pskset -> new PossibleSecret(Secret.PRESHARED_KEY, pskset.getPreSharedKey()))
                    .collect(Collectors.toList()));
            }
        } else {
            secretList.add(new PossibleSecret(Secret.PREMASTER_SECRET, context.getPreMasterSecret()));
            secretList.add(new PossibleSecret(Secret.MASTER_SECRET, context.getMasterSecret()));
        }
        return secretList;
    }

    public static List<Ticket> getSessionTickets(State state) {
        if (state.getTlsContext() == null || state.getTlsContext().getSelectedProtocolVersion() == null) {
            return Collections.emptyList();
        }
        List<PossibleSecret> possibleSecrets = generateSecretList(state);
        TlsContext context = state.getTlsContext();
        if (context.getSelectedProtocolVersion().isTLS13()) {
            return context.getPskSets().stream().map(pskset -> new TicketTls13(pskset, possibleSecrets))
                .collect(Collectors.toList());
        } else {
            if (context.getLatestSessionTicket() == null) {
                return new ArrayList<>();
            }
            return Arrays
                .asList(new TicketTls12(context.getLatestSessionTicket(), context.getMasterSecret(), possibleSecrets));
        }
    }

}
