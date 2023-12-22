/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import java.util.Objects;

public class TicketBitFlipVector implements TicketVector {
    public final int position;

    public TicketBitFlipVector(int position) {
        this.position = position;
    }

    public ModifiedTicket createTicket(Ticket originalTicket) {
        return new ModifiedTicket(originalTicket, getBitFlipModification());
    }

    private VariableModification<byte[]> getBitFlipModification() {
        // bit 0 is most significant/leftmost
        int byteIndex = position / 8;
        int bitIndex =
                7 - (position % 8); // 0 -> 7, 1 -> 6, ..., 7 -> 0 i.e. 0 leftmost, 7 rightmost
        byte[] xorValue = new byte[] {(byte) (1 << bitIndex & 0xff)};
        return ByteArrayModificationFactory.xor(xorValue, byteIndex);
    }

    @Override
    public String getName() {
        return String.format("BitFlip @ %d", position);
    }

    @Override
    public String toString() {
        return String.format("{position=%d}", position);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof TicketBitFlipVector)) {
            return false;
        }
        TicketBitFlipVector ticketBitFlipVector = (TicketBitFlipVector) o;
        return position == ticketBitFlipVector.position;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(position);
    }
}
