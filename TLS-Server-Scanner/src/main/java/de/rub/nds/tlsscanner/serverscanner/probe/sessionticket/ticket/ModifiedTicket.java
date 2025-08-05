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

    /**
     * Constructs a ModifiedTicket with an original ticket and a modification to apply.
     *
     * @param originalTicket The original ticket to modify
     * @param modification The modification to apply to the ticket bytes
     */
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

    /**
     * Gets the modification applied to the original ticket.
     *
     * @return The variable modification
     */
    public VariableModification<byte[]> getModification() {
        return this.modification;
    }

    /**
     * Gets the original ticket before modification.
     *
     * @return The original ticket
     */
    public Ticket getOriginalTicket() {
        return originalTicket;
    }

    /**
     * Gets the ticket after applying the modification.
     *
     * @return The modified ticket
     */
    public Ticket getResultingTicket() {
        return this.resultingTicket;
    }
}
