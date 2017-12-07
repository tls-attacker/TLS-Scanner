/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
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

    public ExtensionResult(List<ExtensionType> allSupportedExtensions) {
        super(ProbeType.EXTENSIONS);
        this.allSupportedExtensions = allSupportedExtensions;
    }

    @Override
    public void merge(SiteReport report) {
        report.setSupportedExtensions(allSupportedExtensions);
        for (ExtensionType type : allSupportedExtensions) {
            if (type == ExtensionType.ENCRYPT_THEN_MAC) {
                extendedMasterSecret = true;
            }
            if (type == ExtensionType.EXTENDED_MASTER_SECRET) {
                encryptThenMac = true;
            }
            if (type == ExtensionType.RENEGOTIATION_INFO) {
                secureRenegotiation = true;
            }
        }
        report.setSupportsExtendedMasterSecret(extendedMasterSecret);
        report.setSupportsEncryptThenMacSecret(encryptThenMac);
        report.setSupportsSecureRenegotiation(secureRenegotiation);
    }

}
