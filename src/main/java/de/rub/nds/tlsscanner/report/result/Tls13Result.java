package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class Tls13Result extends ProbeResult {

    private final List<ProtocolVersion> supportedProtocolVersion;

    private final List<ProtocolVersion> unsupportedProtocolVersion;

    private final List<NamedGroup> supportedNamedGroups;
    
    private final List<CipherSuite> supportedCipherSuites;

    public Tls13Result(List<ProtocolVersion> supportedProtocolVersion, List<ProtocolVersion> unsupportedProtocolVersion, List<NamedGroup> supportedNamedGroups, List<CipherSuite> supportedCipherSuites) {
        super(ProbeType.TLS13);
        this.supportedProtocolVersion = supportedProtocolVersion;
        this.unsupportedProtocolVersion = unsupportedProtocolVersion;
        this.supportedNamedGroups = supportedNamedGroups;
        this.supportedCipherSuites = supportedCipherSuites;
    }

    @Override
    public void merge(SiteReport report) {
        for (ProtocolVersion version : supportedProtocolVersion) {
            if (version == ProtocolVersion.TLS13) {
                report.setSupportsTls13(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT14) {
                report.setSupportsTls13Draft14(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT15) {
                report.setSupportsTls13Draft15(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT16) {
                report.setSupportsTls13Draft16(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT17) {
                report.setSupportsTls13Draft17(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT18) {
                report.setSupportsTls13Draft18(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT19) {
                report.setSupportsTls13Draft19(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT20) {
                report.setSupportsTls13Draft20(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT21) {
                report.setSupportsTls13Draft21(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT22) {
                report.setSupportsTls13Draft22(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT23) {
                report.setSupportsTls13Draft23(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT24) {
                report.setSupportsTls13Draft24(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT25) {
                report.setSupportsTls13Draft25(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT26) {
                report.setSupportsTls13Draft26(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT27) {
                report.setSupportsTls13Draft27(true);
            }
            if (version == ProtocolVersion.TLS13_DRAFT28) {
                report.setSupportsTls13Draft28(true);
            }
        }
        for (ProtocolVersion version : unsupportedProtocolVersion) {
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
            if (version == ProtocolVersion.TLS13_DRAFT23) {
                report.setSupportsTls13Draft23(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT24) {
                report.setSupportsTls13Draft24(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT25) {
                report.setSupportsTls13Draft25(false);
            }
            if (version == ProtocolVersion.TLS13_DRAFT26) {
                report.setSupportsTls13Draft26(false);
            }
        }
        report.setSupportedTls13Groups(supportedNamedGroups);
        report.setSupportedTls13CipherSuites(supportedCipherSuites);
    }
}
