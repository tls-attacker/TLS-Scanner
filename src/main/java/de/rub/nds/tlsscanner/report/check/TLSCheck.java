/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.check;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSCheck {

    private final CheckType type;
    private final boolean result;

    public TLSCheck(boolean result, CheckType type) {
        this.result = result;
        this.type = type;
    }

    public CheckType getType() {
        return type;
    }


    public String getName() {
        return type.name();
    }

    public boolean isResult() {
        return result;
    }

    @Override
    public String toString() {
        return "name=" + getName() + "\tresult=" + result;
    }
}
