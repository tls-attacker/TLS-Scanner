/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentResult;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public abstract class TicketResult extends VersionDependentResult {

    private List<Ticket> ticketList = new LinkedList<>();

    private TestResults issuesTickets;
    private TestResults resumesWithTicket;
    private TestResults replayVulnerable;
    private TestResults allowsCiphersuiteChange;
    private Map<ProtocolVersion, TestResults> versionChangeResults =
            new EnumMap<>(ProtocolVersion.class);

    public static TicketResult create(ProtocolVersion version) {
        return create(version, TestResults.NOT_TESTED_YET);
    }

    public static TicketResult create(ProtocolVersion version, TestResults result) {
        switch (version) {
            case TLS10:
            case TLS11:
            case TLS12:
                return new TicketResultPre13(version, result);
            case TLS13:
                return new TicketResultTls13(result);
            default:
                return null;
        }
    }

    protected TicketResult(ProtocolVersion protocolVersion, TestResults result) {
        super(protocolVersion);
        this.issuesTickets = result;
        this.resumesWithTicket = result;
        this.replayVulnerable = result;
        this.allowsCiphersuiteChange = result;
    }

    @Override
    public final void writeToServerReport(ServerReport report) {
        for (Entry<ProtocolVersion, TestResults> changeResult : versionChangeResults.entrySet()) {
            assert changeResult.getKey() != getProtocolVersion()
                    : "versionChangeResults must not contain result for tested version (would test whether ticket can be resumed in issued version)";
            putResult(
                    report,
                    TlsAnalyzedProperty.VERSION_CHANGE_TICKET,
                    changeResult.getValue(),
                    true);
        }
        putResult(report, TlsAnalyzedProperty.ISSUES_TICKET, this.getIssuesTickets(), true);
        putResult(
                report, TlsAnalyzedProperty.RESUMES_WITH_TICKET, this.getResumesWithTicket(), true);
        putResult(
                report,
                TlsAnalyzedProperty.REPLAY_VULNERABLE_TICKET,
                this.getReplayVulnerable(),
                true);
        putResult(
                report,
                TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET,
                this.getAllowsCiphersuiteChange(),
                true);

        writeToServerReportVersionSpecific(report);
    }

    public abstract void writeToServerReportVersionSpecific(ServerReport report);

    public List<Ticket> getTicketList() {
        return ticketList;
    }

    public void setTicketList(List<Ticket> ticketList) {
        this.ticketList = ticketList;
    }

    public TestResults getIssuesTickets() {
        return issuesTickets;
    }

    public void setIssuesTickets(TestResults issuesTickets) {
        this.issuesTickets = issuesTickets;
    }

    public TestResults getResumesWithTicket() {
        return resumesWithTicket;
    }

    public void setResumesWithTicket(TestResults resumesWithTicket) {
        this.resumesWithTicket = resumesWithTicket;
    }

    public TestResults getReplayVulnerable() {
        return replayVulnerable;
    }

    public void setReplayVulnerable(TestResults replayVulnerable) {
        this.replayVulnerable = replayVulnerable;
    }

    public TestResults getAllowsCiphersuiteChange() {
        return allowsCiphersuiteChange;
    }

    public void setAllowsCiphersuiteChange(TestResults allowsCiphersuiteChange) {
        this.allowsCiphersuiteChange = allowsCiphersuiteChange;
    }

    public Map<ProtocolVersion, TestResults> getVersionChangeResults() {
        return versionChangeResults;
    }

    public void setVersionChangeResult(ProtocolVersion version, TestResults result) {
        versionChangeResults.put(version, result);
    }
}
