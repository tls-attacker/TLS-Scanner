/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class NamedGroupResult extends ProbeResult {

    private final List<NamedGroup> namedGroupsList;
    private final List<NamedGroup> tls13NamedGroupsList;

    public NamedGroupResult(List<NamedGroup> groups, List<NamedGroup> tls13Groups) {
        super(ProbeType.NAMED_GROUPS);
        this.namedGroupsList = groups;
        this.tls13NamedGroupsList = tls13Groups;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedNamedGroups(namedGroupsList);
        report.setSupportedTls13Groups(tls13NamedGroupsList);
    }

}
