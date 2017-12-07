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
public class TlsCheck {

    private final CheckType type;
    private final boolean result;
    private final int score;
    private final boolean didError;

    public TlsCheck(boolean result, CheckType type, int score) {
        this.result = result;
        this.type = type;
        this.score = score;
        this.didError = false;
    }

    public TlsCheck(CheckType type, boolean result, int score, boolean didError) {
        this.type = type;
        this.result = result;
        this.score = score;
        this.didError = didError;
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

    public int getScore() {
        return score;
    }

    @Override
    public String toString() {
        return "name=" + getName() + "\tresult=" + result;
    }
}
