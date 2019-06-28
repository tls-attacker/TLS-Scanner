/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class ExtensionResult extends ProbeResult {

    private List<ExtensionType> allSupportedExtensions;
    private boolean extendedMasterSecret = false;
    private boolean encryptThenMac = false;
    private boolean secureRenegotiation = false;
    private boolean sessionTickets = false;

    public ExtensionResult(List<ExtensionType> allSupportedExtensions) {
        super(ProbeType.EXTENSIONS);
        this.allSupportedExtensions = allSupportedExtensions;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (report.getSupportedExtensions() == null) {
            report.setSupportedExtensions(allSupportedExtensions);
        } else {
            report.getSupportedExtensions().addAll(allSupportedExtensions);
        }
        for (ExtensionType type : allSupportedExtensions) {
            if (type == ExtensionType.ENCRYPT_THEN_MAC) {
                encryptThenMac = true;
            }
            if (type == ExtensionType.EXTENDED_MASTER_SECRET) {
                extendedMasterSecret = true;
            }
            if (type == ExtensionType.RENEGOTIATION_INFO) {
                secureRenegotiation = true;
            }
            if (type == ExtensionType.SESSION_TICKET) {
                sessionTickets = true;
            }
        }
        report.setSupportsExtendedMasterSecret(extendedMasterSecret);
        report.setSupportsEncryptThenMacSecret(encryptThenMac);
        report.setSupportsSecureRenegotiation(secureRenegotiation);
        report.setSupportsSessionTicket(sessionTickets);
    }

}
