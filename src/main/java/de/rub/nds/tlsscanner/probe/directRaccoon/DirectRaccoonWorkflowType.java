/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.directRaccoon;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public enum DirectRaccoonWorkflowType {
    
    /**
     *
     */
    INITIAL("Complete TLS protocol flow with CCS and Finished messages"),
    /**
     *
     */
    CKE("TLS protocol flow with missing CCS and Finished messages"),
    /**
     *
     */
    CKE_CCS("TLS protocol flow with missing Finished message"),
    /**
     *
     */
    CKE_CCS_FIN("Complete TLS protocol flow with CCS and Finished messages");

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
