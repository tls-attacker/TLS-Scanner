/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

public class GuidelineCheckResult {

    private final String name;
    private final String detail;
    private final GuidelineCheckStatus status;

    public GuidelineCheckResult(String name, String detail, GuidelineCheckStatus status) {
        this.name = name;
        this.detail = detail;
        this.status = status;
    }

    public String getName() {
        return name;
    }

    public String getDetail() {
        return detail;
    }

    public GuidelineCheckStatus getStatus() {
        return status;
    }
}
