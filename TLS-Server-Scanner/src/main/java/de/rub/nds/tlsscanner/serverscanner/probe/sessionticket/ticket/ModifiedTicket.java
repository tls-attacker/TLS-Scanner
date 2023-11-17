/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import de.rub.nds.modifiablevariable.VariableModification;

public class ModifiedTicket {
    private final Ticket originalTicket;

    private final VariableModification<byte[]> modification;

    private final Ticket resultingTicket;

    public ModifiedTicket(Ticket originalTicket, VariableModification<byte[]> modification) {
        this.originalTicket = originalTicket;
        this.modification = modification;
        this.resultingTicket = computeResultingTicket();
    }

    private Ticket computeResultingTicket() {
        if (modification == null) {
            return originalTicket;
        }
        Ticket newTicket = originalTicket.copy();
        byte[] newBytes = modification.modify(newTicket.getTicketBytesOriginal());
        newTicket.setTicketBytes(newBytes);
        return newTicket;
    }

    public VariableModification<byte[]> getModification() {
        return this.modification;
    }

    public Ticket getOriginalTicket() {
        return originalTicket;
    }

    public Ticket getResultingTicket() {
        return this.resultingTicket;
    }
}
