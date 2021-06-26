/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import java.util.List;

public class GuidelineReport {

    private String name;
    private String link;
    private List<GuidelineCheckResult> results;
    private List<GuidelineCheckResult> skipped;

    public GuidelineReport(String name, String link, List<GuidelineCheckResult> results,
        List<GuidelineCheckResult> skipped) {
        this.name = name;
        this.link = link;
        this.results = results;
        this.skipped = skipped;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public List<GuidelineCheckResult> getResults() {
        return results;
    }

    public void setResults(List<GuidelineCheckResult> results) {
        this.results = results;
    }

    public List<GuidelineCheckResult> getSkipped() {
        return skipped;
    }

    public void setSkipped(List<GuidelineCheckResult> skipped) {
        this.skipped = skipped;
    }
}
