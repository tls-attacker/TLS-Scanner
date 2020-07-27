/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class NamedGroupResult extends ProbeResult {

    private final List<NamedGroup> namedGroupsList;

    public NamedGroupResult(List<NamedGroup> groups) {
        super(ProbeType.NAMED_GROUPS);
        this.namedGroupsList = groups;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedNamedGroups(namedGroupsList);
    }

}
