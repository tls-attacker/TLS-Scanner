/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.Objects;
import java.util.stream.Collector;

/**
 * A list of tickets for a specific protocol version. Usually this contains the tickets of a single
 * connection.
 *
 * <p>This came into existence for the SessionTicketExtractor, because generics in generics can be
 * annoying.
 */
public class TicketHolder extends LinkedList<Ticket> {
    /**
     * Creates a collector for collecting tickets into a TicketHolder for a specific protocol
     * version.
     *
     * @param protocolVersion The protocol version for the tickets being collected
     * @return A collector that accumulates tickets into a TicketHolder
     */
    public static Collector<Ticket, ?, TicketHolder> collector(ProtocolVersion protocolVersion) {
        return Collector.of(
                () -> new TicketHolder(protocolVersion),
                TicketHolder::add,
                (left, right) -> {
                    left.addAll(right);
                    return left;
                });
    }

    private final ProtocolVersion protocolVersion;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private TicketHolder() {
        this.protocolVersion = null;
    }

    /**
     * Constructs a new empty TicketHolder for the specified protocol version.
     *
     * @param protocolVersion The protocol version for tickets in this holder
     */
    public TicketHolder(ProtocolVersion protocolVersion) {
        super();
        this.protocolVersion = protocolVersion;
    }

    /**
     * Constructs a new TicketHolder with an initial ticket for the specified protocol version.
     *
     * @param protocolVersion The protocol version for tickets in this holder
     * @param ticket The initial ticket to add to the holder
     */
    public TicketHolder(ProtocolVersion protocolVersion, Ticket ticket) {
        this(protocolVersion);
        add(ticket);
    }

    /**
     * Gets the protocol version associated with this ticket holder.
     *
     * @return The protocol version
     */
    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Checks if this TicketHolder is equal to another object.
     *
     * @param o The object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        TicketHolder tickets = (TicketHolder) o;
        return protocolVersion == tickets.protocolVersion;
    }

    /**
     * Returns the hash code value for this TicketHolder.
     *
     * @return The hash code value
     */
    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), protocolVersion);
    }
}
