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

public class TicketPoVectorSecond implements TicketPoVector {
    public final Integer offset;
    public final Byte lastXorValue;
    public final Byte lastAssumedPlaintext;
    public final Byte secondXorValue;
    public final Byte secondAssumedPlaintext;

    public TicketPoVectorSecond(Integer offset, Byte lastXorValue, Byte lastAssumedPlaintext, Byte secondXorValue,
        Byte secondAssumedPlaintext) {
        this.offset = offset;
        this.lastXorValue = lastXorValue;
        this.lastAssumedPlaintext = lastAssumedPlaintext;
        this.secondXorValue = secondXorValue;
        this.secondAssumedPlaintext = secondAssumedPlaintext;
    }

    public ModifiedTicket createTicket(Ticket originalTicket, byte prefixXorValue) {
        // -1 to correctly count from the back (e.g. offset=0 is transformed to -1)
        // -2 because we want to also xor the prefix value and hit the second to last byte instead of the last byte
        return new ModifiedTicket(originalTicket,
            new ByteArrayXorModification(new byte[] { prefixXorValue, secondXorValue, lastXorValue }, -offset - 1 - 2));
    }

    @Override
    public String getName() {
        return String.format("Padding XOR %02x%02x @ %d (assuming plain=%02x%02x)", secondXorValue, lastXorValue,
            offset, secondAssumedPlaintext, lastAssumedPlaintext);
    }

    @Override
    public String toString() {
        return String.format(
            "{offset=%d, lastXorValue=%02x, lastAssumedPlaintext=%02x, secondXorValue=%02x, secondAssumedPlaintext=%02x}",
            offset, lastXorValue, lastAssumedPlaintext, secondXorValue, secondAssumedPlaintext);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof TicketPoVectorSecond)) {
            return false;
        }
        TicketPoVectorSecond ticketPoVectorSecond = (TicketPoVectorSecond) o;
        return Objects.equals(offset, ticketPoVectorSecond.offset)
            && Objects.equals(lastXorValue, ticketPoVectorSecond.lastXorValue)
            && Objects.equals(lastAssumedPlaintext, ticketPoVectorSecond.lastAssumedPlaintext)
            && Objects.equals(secondXorValue, ticketPoVectorSecond.secondXorValue)
            && Objects.equals(secondAssumedPlaintext, ticketPoVectorSecond.secondAssumedPlaintext);
    }

    @Override
    public int hashCode() {
        return Objects.hash(offset, lastXorValue, lastAssumedPlaintext, secondXorValue, secondAssumedPlaintext);
    }

}
