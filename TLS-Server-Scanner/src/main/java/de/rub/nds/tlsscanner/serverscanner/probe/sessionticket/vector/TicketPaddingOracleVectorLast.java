/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import java.util.Objects;

public class TicketPaddingOracleVectorLast implements TicketPaddingOracleVector {
    /**
     * Offset (from the right) where we find the last byte of the padding. 0 means the last byte is
     * padding. 1 means the last byte is something else, but the second to last byte is padding.
     */
    public final Integer offset;
    /** Value to xor onto the last padding byte */
    public final Byte xorValue;

    /* We need to subtract 2 from the offset:
    -1 to correctly count from the back (e.g. offset=0 is transformed to -1).
    -1 because we want to xor the previous byte with the prefixXorValue.
    */
    private final int CREATE_TICKET_XOR_OFFSET = 2;

    public TicketPaddingOracleVectorLast(Integer offset, Byte xorValue) {
        this.offset = offset;
        this.xorValue = xorValue;
    }

    public ModifiedTicket createTicket(Ticket originalTicket, byte prefixXorValue) {
        return new ModifiedTicket(
                originalTicket,
                new ByteArrayXorModification(
                        new byte[] {prefixXorValue, xorValue}, -offset - CREATE_TICKET_XOR_OFFSET));
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
        if (o == this) return true;
        if (!(o instanceof TicketPaddingOracleVectorLast)) {
            return false;
        }
        TicketPaddingOracleVectorLast ticketPaddingOracleLastByteVector =
                (TicketPaddingOracleVectorLast) o;
        return Objects.equals(offset, ticketPaddingOracleLastByteVector.offset)
                && Objects.equals(xorValue, ticketPaddingOracleLastByteVector.xorValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(offset, xorValue);
    }
}
