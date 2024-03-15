/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import com.fasterxml.jackson.annotation.JsonInclude;
import de.rub.nds.scanner.core.constants.TestResult;
import jakarta.xml.bind.annotation.XmlAnyElement;

@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class GuidelineCheckResult {

    private String id;
    private String name;

    @XmlAnyElement(lax = true)
    private TestResult result;

    private GuidelineCheckCondition condition;

    public GuidelineCheckResult(TestResult result) {
        this.result = result;
    }

    public abstract String display();

    public final String getId() {
        return id;
    }

    public final void setId(String id) {
        this.id = id;
    }

    public final String getName() {
        return name;
    }

    public final void setName(String name) {
        this.name = name;
    }

    public final TestResult getResult() {
        return result;
    }

    public final void setResult(TestResult result) {
        this.result = result;
    }

    public GuidelineCheckCondition getCondition() {
        return condition;
    }

    public void setCondition(GuidelineCheckCondition condition) {
        this.condition = condition;
    }
}
