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

    public TicketHolder(ProtocolVersion protocolVersion) {
        super();
        this.protocolVersion = protocolVersion;
    }

    public TicketHolder(ProtocolVersion protocolVersion, Ticket ticket) {
        this(protocolVersion);
        add(ticket);
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        TicketHolder tickets = (TicketHolder) o;
        return protocolVersion == tickets.protocolVersion;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), protocolVersion);
    }
}
