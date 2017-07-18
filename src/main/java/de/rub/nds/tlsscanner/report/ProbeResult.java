/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.probe.ProbeType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProbeResult {

    private final ProbeType type;
    private final List<ResultValue> resultList;
    private final List<TLSCheck> checkList;

    public ProbeResult(ProbeType type, List<ResultValue> resultList, List<TLSCheck> checkList) {
        this.type = type;
        this.resultList = resultList;
        this.checkList = checkList;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(type.name());
        builder.append(":");
        builder.append("\n");
        for (ResultValue value : resultList) {
            builder.append(value.toString());
            builder.append("\n");
        }
        builder.append("Checks:\n");
        builder.append(getCheckString());
        return builder.toString();
    }

    public String getCheckString() {
        StringBuilder builder = new StringBuilder();
        for (TLSCheck check : checkList) {
            if (check != null) {
                builder.append(check.toString());
                builder.append("\n");
            }
        }
        return builder.toString();
    }

    public List<TLSCheck> getCheckList() {
        return checkList;
    }

    public boolean hasFailedCheck() {
        for (TLSCheck check : checkList) {
            if (check.isResult()) {
                return true;
            }
        }
        return false;
    }

    public String getProbeName() {
        return type.name();
    }
}
