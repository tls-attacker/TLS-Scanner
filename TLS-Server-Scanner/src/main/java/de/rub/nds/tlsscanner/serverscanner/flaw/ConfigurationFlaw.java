/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.flaw;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class ConfigurationFlaw {

    private String flawName;
    private FlawLevel flawLevel;
    private String flawDescription;
    private String howToFix;

    public ConfigurationFlaw(String flawName, FlawLevel flawLevel, String flawDescription, String howToFix) {
        this.flawName = flawName;
        this.flawLevel = flawLevel;
        this.flawDescription = flawDescription;
        this.howToFix = howToFix;
    }

    public String getFlawName() {
        return flawName;
    }

    public void setFlawName(String flawName) {
        this.flawName = flawName;
    }

    public FlawLevel getFlawLevel() {
        return flawLevel;
    }

    public void setFlawLevel(FlawLevel flawLevel) {
        this.flawLevel = flawLevel;
    }

    public String getFlawDescription() {
        return flawDescription;
    }

    public void setFlawDescription(String flawDescription) {
        this.flawDescription = flawDescription;
    }

    public String getHowToFix() {
        return howToFix;
    }

    public void setHowToFix(String howToFix) {
        this.howToFix = howToFix;
    }

    @Override
    public String toString() {
        return "" + flawName + ", " + flawLevel + ": " + flawDescription + ". " + howToFix;
    }

}
