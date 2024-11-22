/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.mac;

import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.constants.CheckPatternType;
import java.util.List;

public class CheckPattern {

    private CheckPatternType type;

    private boolean foundFinishedAndAlert;

    private ByteCheckStatus[] bytePattern;

    private List<ResponseFingerprint> responseFingerprintList = null;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private CheckPattern() {}

    public CheckPattern(
            CheckPatternType type, boolean foundFinishedAndAlert, ByteCheckStatus[] bytePattern) {
        this.type = type;
        this.foundFinishedAndAlert = foundFinishedAndAlert;
        this.bytePattern = bytePattern;
    }

    public List<ResponseFingerprint> getResponseFingerprintList() {
        return responseFingerprintList;
    }

    public void setResponseFingerprintList(List<ResponseFingerprint> responseFingerprintList) {
        this.responseFingerprintList = responseFingerprintList;
    }

    public CheckPatternType getType() {
        return type;
    }

    public void setType(CheckPatternType type) {
        this.type = type;
    }

    public ByteCheckStatus[] getBytePattern() {
        return bytePattern;
    }

    public void setBytePattern(ByteCheckStatus[] bytePattern) {
        this.bytePattern = bytePattern;
    }

    public boolean isFoundFinishedAndAlert() {
        return foundFinishedAndAlert;
    }

    public void setFoundFinishedAndAlert(boolean foundFinishedAndAlert) {
        this.foundFinishedAndAlert = foundFinishedAndAlert;
    }

    @Override
    public String toString() {
        switch (type) {
            case CORRECT:
                return "correct";
            case NONE:
                return "not checked" + (foundFinishedAndAlert ? " - found finished and Alert" : "");
            case PARTIAL:
                StringBuilder builder = new StringBuilder("Partial");
                if (foundFinishedAndAlert) {
                    builder.append(" - found finished and alert");
                }
                for (ByteCheckStatus b : bytePattern) {
                    builder.append(" - ");
                    builder.append(b == ByteCheckStatus.CHECKED ? "checked" : "not checked");
                }
                return builder.toString();
            case UNKNOWN:
                return "Unknown";
            default:
                return super.toString();
        }
    }
}
