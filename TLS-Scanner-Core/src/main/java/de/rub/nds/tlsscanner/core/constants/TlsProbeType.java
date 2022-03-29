/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.constants.ProbeType;
import javax.xml.bind.annotation.XmlRootElement;

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
    SNI("Server name indication (SNI)"),
    HANDSHAKE_SIMULATION("Handshake simulation"),
    MAC("MAC"),
    CCA_SUPPORT("Client certificate authenication support"),
    CCA_REQUIRED("Client certificate authenication required"),
    CCA("Client certificate authenication bypasses"),
    DIRECT_RACCOON("Direct RACCOON"),
    EC_POINT_FORMAT("EC point formats"),
    RACCOON_ATTACK("RACCOON attack"),
    DTLS_HELLO_VERIFY_REQUEST("DTLS hello verify request"),
    DTLS_COMMON_BUGS("DTLS common bugs"),
    DTLS_FEATURES("DTLS features"),
    DTLS_MESSAGE_SEQUENCE_NUMBER("DTLS message sequence number"),
    DTLS_RETRANSMISSIONS("DTLS retransmissions"),
    HTTP_FALSE_START("HTTP false start"),
    HELLO_RETRY("Hello retry"),
    CROSS_PROTOCOL_ALPACA("Alpaca attack"),
    RANDOMNESS("Randomness"),
    TLS_FALLBACK_SCSV("TLS Fallback SCSV"),
    // CLIENT SPECIFIC PROBES
    FORCED_COMPRESSION("Forced Compression"),
    FREAK("Freak"),
    VERSION_1_3_RANDOM_DOWNGRADE("TLS 1.3 DOWNGRADE Prevention"),
    DH_PARAMETERS("DH Parameter"),
    BASIC("Basic");

    @Override
    public String getName() {
        return humanReadableName;
    }

    private String humanReadableName;

    private TlsProbeType(String humanReadableName) {
        this.humanReadableName = humanReadableName;
    }
}
