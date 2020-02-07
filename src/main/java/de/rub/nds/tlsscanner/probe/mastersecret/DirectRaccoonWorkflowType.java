/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.mastersecret;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public enum DirectRaccoonWorkflowType {
    
    /**
     *
     */
    INITIAL("Complete TLS protocol flow"),
    /**
     *
     */
    CKE_CCS_FIN("Protocol flow with CKE, CCS and FIN messages"),
    /**
     *
     */
    CKE("Protocol flow with CKE messages"),
    /**
     *
     */
    CKE_CCS("Protocol flow with CKE and CCS messages");

    String description;

    DirectRaccoonWorkflowType(String description) {
        this.description = description;
    }

    /**
     *
     * @return
     */
    public String getDescription() {
        return description;
    }   
}
