/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum HandshakeInsecure {
    CIPHERSUITE_GRADE_LOW ("grade of the selected ciphersuite is low"),
    PADDING_ORACLE ("connection is vulnerable to padding oracle"),
    BLEICHENBACHER ("connection is vulnerable to bleichenbacher"),
    CRIME ("connection is vulnerable to crime"),
    SWEET32 ("connection is vulnerable to sweet32"),
    UNKNOWN ("reason can not be specified");
    
    private final String reason;
    
    private HandshakeInsecure(String reason) {    
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}