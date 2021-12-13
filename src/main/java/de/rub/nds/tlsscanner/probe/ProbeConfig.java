/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import java.io.Serializable;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProbeConfig implements Serializable {

    private String successName;
    private String successDescription;

    public ProbeConfig(String successName, String successDescription) {
        this.successName = successName;
        this.successDescription = successDescription;
    }

    public ProbeConfig() {
    }

    public String getSuccessName() {
        return successName;
    }

    public void setSuccessName(String successName) {
        this.successName = successName;
    }

    public String getSuccessDescription() {
        return successDescription;
    }

    public void setSuccessDescription(String successDescription) {
        this.successDescription = successDescription;
    }
}
