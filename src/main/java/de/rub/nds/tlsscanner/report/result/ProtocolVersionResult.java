/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class ProtocolVersionResult extends ProbeResult {

    private final List<ProtocolVersion> supportedProtocolVersions;

    private final List<ProtocolVersion> unsupportedProtocolVersions;

    public ProtocolVersionResult(List<ProtocolVersion> supportedProtocolVersions, List<ProtocolVersion> unsupportedProtocolVersions) {
        super(ProbeType.PROTOCOL_VERSION);
        this.supportedProtocolVersions = supportedProtocolVersions;
        this.unsupportedProtocolVersions = unsupportedProtocolVersions;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (supportedProtocolVersions.size() > 0) {
            report.setSupportsSslTls(true);
        }
        report.setVersions(supportedProtocolVersions);
        for (ProtocolVersion version : supportedProtocolVersions) {
            if (version == ProtocolVersion.DTLS10) {
                report.setSupportsDtls10(true);
            }
            if (version == ProtocolVersion.DTLS12) {
                report.setSupportsDtls12(true);
            }
            if (version == ProtocolVersion.SSL2) {
                report.setSupportsSsl2(true);
            }
            if (version == ProtocolVersion.SSL3) {
                report.setSupportsSsl3(true);
            }
            if (version == ProtocolVersion.TLS10) {
                report.setSupportsTls10(true);
            }
            if (version == ProtocolVersion.TLS11) {
                report.setSupportsTls11(true);
            }
            if (version == ProtocolVersion.TLS12) {
                report.setSupportsTls12(true);
            }
        }

        for (ProtocolVersion version : unsupportedProtocolVersions) {
            if (version == ProtocolVersion.DTLS10) {
                report.setSupportsDtls10(false);
            }
            if (version == ProtocolVersion.DTLS12) {
                report.setSupportsDtls12(false);
            }
            if (version == ProtocolVersion.SSL2) {
                report.setSupportsSsl2(false);
            }
            if (version == ProtocolVersion.SSL3) {
                report.setSupportsSsl3(false);
            }
            if (version == ProtocolVersion.TLS10) {
                report.setSupportsTls10(false);
            }
            if (version == ProtocolVersion.TLS11) {
                report.setSupportsTls11(false);
            }
            if (version == ProtocolVersion.TLS12) {
                report.setSupportsTls12(false);
            }
            if (version == ProtocolVersion.TLS13) {
                report.setSupportsTls13(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT14) {
                report.setSupportsTls13Draft14(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT15) {
                report.setSupportsTls13Draft15(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT16) {
                report.setSupportsTls13Draft16(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT17) {
                report.setSupportsTls13Draft17(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT18) {
                report.setSupportsTls13Draft18(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT19) {
                report.setSupportsTls13Draft19(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT20) {
                report.setSupportsTls13Draft20(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT21) {
                report.setSupportsTls13Draft21(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT22) {
                report.setSupportsTls13Draft22(false);
            }
        }
        report.setVersions(supportedProtocolVersions);
    }

}
