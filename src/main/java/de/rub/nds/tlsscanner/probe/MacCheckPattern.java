package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.MacCheckPatternType;
import de.rub.nds.tlsscanner.probe.mac.ByteCheckStatus;

public class MacCheckPattern {

    private MacCheckPatternType type;

    private boolean foundFinishedAndAlert;

    private ByteCheckStatus[] bytePattern;

    public MacCheckPattern(MacCheckPatternType type, boolean foundFinishedAndAlert, ByteCheckStatus[] bytePattern) {
        this.type = type;
        this.foundFinishedAndAlert = foundFinishedAndAlert;
        this.bytePattern = bytePattern;
    }

    public MacCheckPatternType getType() {
        return type;
    }

    public void setType(MacCheckPatternType type) {
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

        }
        return super.toString();
    }

}
