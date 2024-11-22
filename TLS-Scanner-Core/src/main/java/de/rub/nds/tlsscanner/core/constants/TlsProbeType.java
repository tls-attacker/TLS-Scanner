/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.probe.ProbeType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public enum TlsProbeType implements ProbeType {
    // SERVER PROBES
    ALPN("ALPN"),
    ESNI("ESNI"),
    CERTIFICATE("Certificate"),
    OCSP("OCSP"),
    CIPHER_SUITE_ORDER("Cipher suite order"),
    CERTIFICATE_TRANSPARENCY("Certificate transparency (CT)"),
    CIPHER_SUITE("Cipher suite"),
    HEARTBLEED("Heartbleed"),
    HTTP_HEADER("HTTP header"),
    BLEICHENBACHER("Bleichenbacher"),
    DROWN("Drown"),
    EARLY_CCS("Early CCS"),
    NAMED_GROUPS("Named groups"),
    NAMED_GROUPS_ORDER("Named groups order"),
    PADDING_ORACLE("Padding oracle"),
    TLS_POODLE("TLS-Poodle"),
    PROTOCOL_VERSION("Protocol version"),
    INVALID_CURVE("Invalid curve"),
    SIGNATURE_AND_HASH("Signature and hash algorithm"),
    SIGNATURE_HASH_ALGORITHM_ORDER("Signature Hash Algorithm Order"),
    EXTENSIONS("Extensions"),
    TOKENBINDING("Tokenbinding"),
    COMPRESSIONS("Compression"),
    COMMON_BUGS("Common bugs"),
    RECORD_FRAGMENTATION("Record fragmentation"),
    RESUMPTION("Resumption"),
    RENEGOTIATION("Renegotiation"),
    SESSION_TICKET_ZERO_KEY("Session ticket zero key"),
    SESSION_TICKET("Session ticket"),
    SESSION_TICKET_COLLECTOR("Session ticket collector for afterprobe"),
    SESSION_TICKET_MANIPULATION("Session ticket manipulation"),
    SESSION_TICKET_PADDING_ORACLE("Session ticket padding oracle"),
    SNI("Server name indication (SNI)"),
    HANDSHAKE_SIMULATION("Handshake simulation"),
    MAC("MAC"),
    CCA_SUPPORT("Client certificate authentication support"),
    CCA_REQUIRED("Client certificate authentication required"),
    CCA("Client certificate authentication bypasses"),
    DIRECT_RACCOON("Direct RACCOON"),
    EC_POINT_FORMAT("EC point formats"),
    RACCOON_ATTACK("RACCOON attack"),
    DTLS_IP_ADDRESS_IN_COOKIE("DTLS ip address in cookie"),
    DTLS_HELLO_VERIFY_REQUEST("DTLS hello verify request"),
    DTLS_COMMON_BUGS("DTLS common bugs"),
    DTLS_REORDERING("DTLS reordering"),
    DTLS_FRAGMENTATION("DTLS fragmentation"),
    DTLS_MESSAGE_SEQUENCE_NUMBER("DTLS message sequence number"),
    DTLS_RETRANSMISSIONS("DTLS retransmissions"),
    DTLS_APPLICATION_FINGERPRINT("DTLS application fingerprint"),
    HTTP_FALSE_START("HTTP false start"),
    HELLO_RETRY("Hello retry"),
    CROSS_PROTOCOL_ALPACA("Alpaca attack"),
    RANDOMNESS("Randomness"),
    TLS_FALLBACK_SCSV("TLS Fallback SCSV"),
    CONNECTION_CLOSING_DELTA("Connection Closing Delta"),
    // CLIENT SPECIFIC PROBES
    FORCED_COMPRESSION("Forced Compression"),
    FREAK("Freak"),
    VERSION_1_3_RANDOM_DOWNGRADE("TLS 1.3 DOWNGRADE Prevention"),
    DHE_PARAMETERS("DHE parameters"),
    BASIC("Basic"),
    APPLICATION_MESSAGE("Application message"),
    SERVER_CERTIFICATE_MINIMUM_KEY_SIZE("Server Certificate Minimum Key Size");

    @Override
    public String getName() {
        return humanReadableName;
    }

    private String humanReadableName;

    private TlsProbeType(String humanReadableName) {
        this.humanReadableName = humanReadableName;
    }
}
