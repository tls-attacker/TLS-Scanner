/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.passive;

import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketHolder;

public class SessionTicketExtractor extends StatExtractor<State, TicketHolder> {

    /** Constructs a new SessionTicketExtractor for extracting session tickets from states. */
    public SessionTicketExtractor() {
        super(TrackableValueType.SESSION_TICKET);
    }

    /**
     * Extracts session tickets from the given state.
     *
     * @param state the state to extract session tickets from
     */
    @Override
    public void extract(State state) {
        TicketHolder tickets = SessionTicketUtil.getSessionTickets(state);
        if (!tickets.isEmpty()) {
            put(tickets);
        }
    }
}
