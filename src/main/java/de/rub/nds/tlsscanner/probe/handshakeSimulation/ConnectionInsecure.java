/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum ConnectionInsecure {
    CIPHERSUITE_GRADE_LOW("Grade of the selected ciphersuite is low"),
    PUBLIC_KEY_SIZE_TOO_SMALL("Server public key parameter is too small (ECRYPT-CSA recommendations 2018)"),
    PADDING_ORACLE("Connection is vulnerable to padding oracle"),
    BLEICHENBACHER("Connection is vulnerable to bleichenbacher"),
    CRIME("Connection is vulnerable to crime"),
    SWEET32("Connection is vulnerable to sweet32");

    private final String reason;

    private ConnectionInsecure(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
