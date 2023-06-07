/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector;

import java.util.Objects;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;

public class TicketPoVectorLast implements TicketPoVector {
    public final Integer offset;
    public final Byte xorValue;

    public TicketPoVectorLast(Integer offset, Byte xorValue) {
        this.offset = offset;
        this.xorValue = xorValue;
    }

    public ModifiedTicket createTicket(Ticket originalTicket, byte prefixXorValue) {
        // -1 to correctly count from the back (e.g. offset=0 is transformed to -1)
        // -1 because we want to also xor the prefix value
        return new ModifiedTicket(originalTicket,
            new ByteArrayXorModification(new byte[] { prefixXorValue, xorValue }, -offset - 1 - 1));
    }

    @Override
    public String getName() {
        return String.format("Padding XOR %02x @ %d", xorValue, offset);
    }

    @Override
    public String toString() {
        return String.format("{offset=%d, xorValue=%02x}", offset, xorValue);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof TicketPoVectorLast)) {
            return false;
        }
        TicketPoVectorLast ticketPaddingOracleLastByteVector = (TicketPoVectorLast) o;
        return Objects.equals(offset, ticketPaddingOracleLastByteVector.offset)
            && Objects.equals(xorValue, ticketPaddingOracleLastByteVector.xorValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(offset, xorValue);
    }

}
