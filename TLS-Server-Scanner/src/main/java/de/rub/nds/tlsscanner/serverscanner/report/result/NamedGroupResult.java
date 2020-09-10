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
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.WitnessType;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class NamedGroupResult extends ProbeResult {

    private final Map<NamedGroup, NamedCurveWitness> namedGroupsMap;
    private final Map<NamedGroup, NamedCurveWitness> namedGroupsMapTls13;

    public NamedGroupResult(Map<NamedGroup, NamedCurveWitness> namedGroupsMap,
            Map<NamedGroup, NamedCurveWitness> namedGroupsMapTls13) {
        super(ProbeType.NAMED_GROUPS);
        this.namedGroupsMap = namedGroupsMap;
        this.namedGroupsMapTls13 = namedGroupsMapTls13;
    }

    @Override
    public void mergeData(SiteReport report) {
        LinkedList<NamedGroup> allGroups = new LinkedList<>();
        if (namedGroupsMap != null) {
            allGroups.addAll(namedGroupsMap.keySet());
        }

        LinkedList<NamedGroup> tls13Groups = new LinkedList<>();
        if (namedGroupsMapTls13 != null) {
            tls13Groups.addAll(namedGroupsMapTls13.keySet());
        }

        report.setSupportedNamedGroups(allGroups);
        report.setSupportedTls13Groups(tls13Groups);
        report.setSupportedNamedGroupsWitnesses(namedGroupsMap);
        report.setSupportedNamedGroupsWitnessesTls13(namedGroupsMapTls13);
    }

}
