/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector;

import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;

public interface TicketPaddingOracleVector extends TicketVector {
    ModifiedTicket createTicket(Ticket originalTicket, byte prefixXorValue);

    @Override
    default ModifiedTicket createTicket(Ticket originalTicket) {
        return createTicket(originalTicket, (byte) 0);
    }
}
