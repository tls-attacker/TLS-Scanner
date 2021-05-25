/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlType;
import java.util.List;

@XmlType(propOrder = { "condition", "cipherSuites" })
public class GuidelineCipherSuites {

    private GuidelineCheckCondition condition;

    private List<CipherSuite> cipherSuites;

    public GuidelineCipherSuites() {
    }

    public GuidelineCipherSuites(GuidelineCheckCondition condition, List<CipherSuite> cipherSuites) {
        this.condition = condition;
        this.cipherSuites = cipherSuites;
    }

    public GuidelineCheckCondition getCondition() {
        return condition;
    }

    @XmlElement(name = "condition")
    public void setCondition(GuidelineCheckCondition condition) {
        this.condition = condition;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    @XmlElement(name = "cipherSuite")
    @XmlElementWrapper(name = "cipherSuites")
    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    @Override
    public String toString() {
        return "GuidelineCipherSuites{" + "condition=" + condition + ", cipherSuites=" + cipherSuites + '}';
    }
}
