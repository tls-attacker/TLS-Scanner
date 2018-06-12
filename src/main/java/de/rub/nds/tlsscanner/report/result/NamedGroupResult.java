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
    public void merge(SiteReport report) {
        report.setSupportedNamedGroups(namedGroupsList);
    }
    
}
