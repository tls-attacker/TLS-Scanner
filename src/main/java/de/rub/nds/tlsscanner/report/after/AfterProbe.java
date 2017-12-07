package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public abstract class AfterProbe {

    public abstract void analyze(SiteReport report);

}
