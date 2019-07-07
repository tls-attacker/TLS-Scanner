/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CompressionsResult extends ProbeResult {

    private List<CompressionMethod> compressions;

    public CompressionsResult(List<CompressionMethod> compressions) {
        super(ProbeType.COMPRESSIONS);
        this.compressions = compressions;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedCompressionMethods(compressions);
        if (compressions.size() > 1) {
            report.setCrimeVulnerable(Boolean.TRUE);
        } else {
            report.setCrimeVulnerable(Boolean.FALSE);
        }
    }

}
