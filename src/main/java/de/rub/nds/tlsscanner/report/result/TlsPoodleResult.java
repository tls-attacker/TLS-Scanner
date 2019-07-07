/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsPoodleResult extends ProbeResult {

    private final Boolean vulnerable;

    public TlsPoodleResult(Boolean vulnerable) {
        super(ProbeType.TLS_POODLE);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setTlsPoodleVulnerable(vulnerable);
    }

}
