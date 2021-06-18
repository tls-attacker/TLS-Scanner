/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.util.List;

@XmlRootElement(name = "guideline")
public class Guideline implements Serializable {

    private String name;
    private String link;
    private List<GuidelineCheck> checks;

    public Guideline() {
    }

    public Guideline(String name, String link, List<GuidelineCheck> checks) {
        this.name = name;
        this.link = link;
        this.checks = checks;
    }

    public String getName() {
        return name;
    }

    @XmlElement(name = "name")
    public void setName(String name) {
        this.name = name;
    }

    public String getLink() {
        return link;
    }

    @XmlElement(name = "link")
    public void setLink(String link) {
        this.link = link;
    }

    public List<GuidelineCheck> getChecks() {
        return checks;
    }

    @XmlElement(name = "check")
    @XmlElementWrapper(name = "checks")
    public void setChecks(List<GuidelineCheck> checks) {
        this.checks = checks;
    }
}
