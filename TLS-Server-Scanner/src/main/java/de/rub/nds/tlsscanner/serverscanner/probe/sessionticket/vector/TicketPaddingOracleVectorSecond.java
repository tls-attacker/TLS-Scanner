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

public class TicketPaddingOracleVectorSecond implements TicketPaddingOracleVector {
    /**
     * Offset (from the right) where we find the last byte of the padding. 0 means the last byte is
     * padding. 1 means the last byte is something else, but the second to last byte is padding.
     */
    public final Integer offset;
    /** Value to xor onto the last padding byte */
    public final Byte lastXorValue;
    /** Assumed plaintext for the last padding byte */
    public final Byte lastAssumedPlaintext;
    /** Value to xor onto the second to last padding byte */
    public final Byte secondXorValue;
    /** Assumed plaintext for the second to last padding byte */
    public final Byte secondAssumedPlaintext;

    /* We need to subtract 3 from the offset:
    -1 to correctly count from the back (e.g. offset=0 is transformed to -1).
    -2 because we want to xor the byte before the second byte with the prefix xor value.
    */
    private final int CREATE_TICKET_XOR_OFFSET = 3;

    public TicketPaddingOracleVectorSecond(
            Integer offset,
            Byte lastXorValue,
            Byte lastAssumedPlaintext,
            Byte secondXorValue,
            Byte secondAssumedPlaintext) {
        this.offset = offset;
        this.lastXorValue = lastXorValue;
        this.lastAssumedPlaintext = lastAssumedPlaintext;
        this.secondXorValue = secondXorValue;
        this.secondAssumedPlaintext = secondAssumedPlaintext;
    }

    public ModifiedTicket createTicket(Ticket originalTicket, byte prefixXorValue) {
        return new ModifiedTicket(
                originalTicket,
                new ByteArrayXorModification(
                        new byte[] {prefixXorValue, secondXorValue, lastXorValue},
                        -offset - CREATE_TICKET_XOR_OFFSET));
    }

    @Override
    public String getName() {
        return String.format(
                "Padding XOR %02x%02x @ %d (assuming plain=%02x%02x)",
                secondXorValue, lastXorValue, offset, secondAssumedPlaintext, lastAssumedPlaintext);
    }

    @Override
    public String toString() {
        return String.format(
                "{offset=%d, lastXorValue=%02x, lastAssumedPlaintext=%02x, secondXorValue=%02x, secondAssumedPlaintext=%02x}",
                offset, lastXorValue, lastAssumedPlaintext, secondXorValue, secondAssumedPlaintext);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof TicketPaddingOracleVectorSecond)) {
            return false;
        }
        TicketPaddingOracleVectorSecond ticketPoVectorSecond = (TicketPaddingOracleVectorSecond) o;
        return Objects.equals(offset, ticketPoVectorSecond.offset)
                && Objects.equals(lastXorValue, ticketPoVectorSecond.lastXorValue)
                && Objects.equals(lastAssumedPlaintext, ticketPoVectorSecond.lastAssumedPlaintext)
                && Objects.equals(secondXorValue, ticketPoVectorSecond.secondXorValue)
                && Objects.equals(
                        secondAssumedPlaintext, ticketPoVectorSecond.secondAssumedPlaintext);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                offset, lastXorValue, lastAssumedPlaintext, secondXorValue, secondAssumedPlaintext);
    }
}
