/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.directraccoon;

public enum DirectRaccoonWorkflowType {

    /** */
    INITIAL("Complete TLS protocol flow with CCS and Finished messages"),
    /** */
    CKE("TLS protocol flow with missing CCS and Finished messages"),
    /** */
    CKE_CCS("TLS protocol flow with missing Finished message"),
    /** */
    CKE_CCS_FIN("Complete TLS protocol flow with CCS and Finished messages");

    String description;

    DirectRaccoonWorkflowType(String description) {
        this.description = description;
    }

    /**
     * Returns the description of this workflow type.
     *
     * @return The description string for this workflow type
     */
    public String getDescription() {
        return description;
    }
}
