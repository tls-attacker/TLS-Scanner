/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.check.TlsCheck;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class ProbeResult {

    private final ProbeType type;

    public ProbeResult(ProbeType type) {
        this.type = type;
    }

    public String getProbeName() {
        return type.name();
    }

    public abstract void merge(SiteReport report);
}
