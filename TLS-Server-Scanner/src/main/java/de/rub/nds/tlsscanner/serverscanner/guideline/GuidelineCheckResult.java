/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import java.util.Objects;

public class GuidelineCheckResult {

    private final String name;
    private final StringBuilder detail = new StringBuilder();

    private GuidelineCheckStatus status;

    public GuidelineCheckResult(String name) {
        this.name = name;
    }

    public GuidelineCheckResult append(Object object) {
        this.detail.append(object);
        return this;
    }

    /**
     * Can be used in case there are multiple checks performed in one {@link GuidelineCheck}.
     * <p>
     * Not a normal setter: The status can only be "worsened". If the status is {@link GuidelineCheckStatus#PASSED} it
     * can be set to {@link GuidelineCheckStatus#UNCERTAIN} or {@link GuidelineCheckStatus#FAILED}. If the status is
     * <code>UNCERTAIN</code> it can be set to <code>FAILED</code>. If the status is <code>FAILED</code> it can no
     * longer be changed.
     *
     * @param status
     *               the status.
     */
    public void updateStatus(GuidelineCheckStatus status) {
        if (this.status == null || status.ordinal() > this.status.ordinal()) {
            this.status = Objects.requireNonNull(status);
        }
    }

    public void update(GuidelineCheckStatus status, String message) {
        this.updateStatus(status);
        this.append(message).append('\n');
    }

    public void setStatus(GuidelineCheckStatus status) {
        this.status = status;
    }

    public String getName() {
        return name;
    }

    public String getDetail() {
        return detail.toString();
    }

    public GuidelineCheckStatus getStatus() {
        return status;
    }
}
