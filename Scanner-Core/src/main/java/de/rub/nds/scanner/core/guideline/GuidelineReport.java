/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import de.rub.nds.scanner.core.constants.TestResults;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class GuidelineReport {

    private String name;
    private String link;
    private List<GuidelineCheckResult> passed;
    private List<GuidelineCheckResult> failed;
    private List<GuidelineCheckResult> uncertain;
    private List<GuidelineCheckResult> skipped;

    public GuidelineReport(String name, String link, List<GuidelineCheckResult> results) {
        this.name = name;
        this.link = link;
        this.passed =
                results.stream()
                        .filter(result -> Objects.equals(TestResults.TRUE, result.getResult()))
                        .collect(Collectors.toList());
        this.failed =
                results.stream()
                        .filter(result -> Objects.equals(TestResults.FALSE, result.getResult()))
                        .collect(Collectors.toList());
        this.skipped =
                results.stream()
                        .filter(
                                result ->
                                        Objects.equals(
                                                TestResults.COULD_NOT_TEST, result.getResult()))
                        .collect(Collectors.toList());
        this.uncertain =
                results.stream()
                        .filter(result -> !Objects.equals(TestResults.TRUE, result.getResult()))
                        .filter(result -> !Objects.equals(TestResults.FALSE, result.getResult()))
                        .filter(
                                result ->
                                        !Objects.equals(
                                                TestResults.COULD_NOT_TEST, result.getResult()))
                        .collect(Collectors.toList());
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

    public List<GuidelineCheckResult> getPassed() {
        return passed;
    }

    public void setPassed(List<GuidelineCheckResult> passed) {
        this.passed = passed;
    }

    public List<GuidelineCheckResult> getFailed() {
        return failed;
    }

    public void setFailed(List<GuidelineCheckResult> failed) {
        this.failed = failed;
    }

    public List<GuidelineCheckResult> getUncertain() {
        return uncertain;
    }

    public void setUncertain(List<GuidelineCheckResult> uncertain) {
        this.uncertain = uncertain;
    }

    public List<GuidelineCheckResult> getSkipped() {
        return skipped;
    }

    public void setSkipped(List<GuidelineCheckResult> skipped) {
        this.skipped = skipped;
    }
}
