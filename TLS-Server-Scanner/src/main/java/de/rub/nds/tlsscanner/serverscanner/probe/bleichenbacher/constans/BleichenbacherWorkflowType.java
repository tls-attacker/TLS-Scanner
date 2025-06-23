/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.bleichenbacher.constans;

public enum BleichenbacherWorkflowType {
    CKE_CCS_FIN("Complete TLS protocol flow with CCS and Finished messages"),
    CKE("TLS protocol flow with missing CCS and Finished messages"),
    CKE_CCS("TLS protocol flow with missing Finished message"),
    CKE_FIN("TLS protocol flow with missing CCS message");

    String description;

    BleichenbacherWorkflowType(String description) {
        this.description = description;
    }

    /**
     * Returns the description of this Bleichenbacher workflow type.
     *
     * @return A string describing the TLS protocol flow characteristics
     */
    public String getDescription() {
        return description;
    }
}
