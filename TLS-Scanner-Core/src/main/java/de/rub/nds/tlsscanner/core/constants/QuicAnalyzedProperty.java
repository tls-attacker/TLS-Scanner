/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "property")
@XmlAccessorType(XmlAccessType.FIELD)
public enum QuicAnalyzedProperty implements AnalyzedProperty {
    // Versions
    SENDS_VERSIONS_NEGOTIATION_PACKET(QuicAnalyzedPropertyCategory.VERSIONS),
    VERSIONS(QuicAnalyzedPropertyCategory.VERSIONS),
    // Transport Parameters
    SENDS_TRANSPORT_PARAMETERS(QuicAnalyzedPropertyCategory.TRANSPORT_PARAMETERS),
    TRANSPORT_PARAMETERS(QuicAnalyzedPropertyCategory.TRANSPORT_PARAMETERS),
    // Quirks
    TLS12_HANDSHAKE_DONE(QuicAnalyzedPropertyCategory.QUIRKS),
    TLS12_HANDSHAKE_CONNECTION_CLOSE_FRAME(QuicAnalyzedPropertyCategory.QUIRKS),
    // Connection Migration
    PORT_CONNECTION_MIGRATION_SUCCESSFUL(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    PORT_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE(
            QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_ADDRESS(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_HANDSHAKE_DONE(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_CONNECTION_MIGRATION_SUCCESSFUL(QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    IPV6_CONNECTION_MIGRATION_WITH_PATH_CHALLANGE(
            QuicAnalyzedPropertyCategory.CONNECTION_MIGRATION),
    // Retry Packet / Token
    RETRY_REQUIRED(QuicAnalyzedPropertyCategory.RETRY_PACKET),
    HAS_RETRY_TOKEN_RETRANSMISSIONS(QuicAnalyzedPropertyCategory.RETRY_PACKET),
    HAS_RETRY_TOKEN_CHECKS(QuicAnalyzedPropertyCategory.RETRY_PACKET),
    RETRY_TOKEN_LENGTH(QuicAnalyzedPropertyCategory.RETRY_PACKET),
    HOLDS_ANTI_DOS_LIMIT(QuicAnalyzedPropertyCategory.RETRY_PACKET),
    // New Token Frame
    IS_NEW_TOKEN_FRAME_SEND(QuicAnalyzedPropertyCategory.NEW_TOKEN_FRAME),
    NUMBER_OF_NEW_TOKEN_FRAMES(QuicAnalyzedPropertyCategory.NEW_TOKEN_FRAME),
    NEW_TOKEN_LENGTH(QuicAnalyzedPropertyCategory.NEW_TOKEN_FRAME),
    // New Connection ID Frame
    IS_NEW_CONNECTION_ID_FRAME_SEND(QuicAnalyzedPropertyCategory.NEW_CONNECTION_ID_FRAME),
    NUMBER_OF_NEW_CONNECTION_ID_FRAMES(QuicAnalyzedPropertyCategory.NEW_CONNECTION_ID_FRAME),
    // Fragmentation
    PROCESSES_SPLITTED_CLIENT_HELLO(QuicAnalyzedPropertyCategory.FRAGMENTATION),
    OVERWRITES_RECEIVED_CRYPTO_FRAMES(QuicAnalyzedPropertyCategory.FRAGMENTATION),
    OVERWRITES_RECEIVED_STREAM_FRAMES(QuicAnalyzedPropertyCategory.FRAGMENTATION);

    private final QuicAnalyzedPropertyCategory category;

    private QuicAnalyzedProperty(QuicAnalyzedPropertyCategory category) {
        this.category = category;
    }

    @Override
    public AnalyzedPropertyCategory getCategory() {
        return category;
    }

    @Override
    public String getName() {
        return name();
    }
}
