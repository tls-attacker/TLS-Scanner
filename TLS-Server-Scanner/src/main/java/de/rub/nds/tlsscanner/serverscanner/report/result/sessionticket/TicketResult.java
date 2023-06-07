/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionDependentResult;

public abstract class TicketResult extends VersionDependentResult {

    private List<Ticket> ticketList = new LinkedList<>();

    private TestResult issuesTickets;
    private TestResult resumesWithTicket;
    private TestResult replayVulnerable;
    private TestResult allowsCiphersuiteChange;
    private Map<ProtocolVersion, TestResult> versionChangeResults = new EnumMap<>(ProtocolVersion.class);

    public static TicketResult create(ProtocolVersion version) {
        return create(version, TestResult.NOT_TESTED_YET);
    }

    public static TicketResult create(ProtocolVersion version, TestResult result) {
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

    protected TicketResult(ProtocolVersion protocolVersion, TestResult result) {
        super(protocolVersion);
        this.issuesTickets = result;
        this.resumesWithTicket = result;
        this.replayVulnerable = result;
        this.allowsCiphersuiteChange = result;
    }

    public final void writeToSiteReport(SiteReport report) {
        for (Entry<ProtocolVersion, TestResult> changeResult : versionChangeResults.entrySet()) {
            assert changeResult.getKey() != getProtocolVersion()
                : "versionChangeResults must not contain result for tested version (would test whether ticket can be resumed in issued version)";
            putResult(report, AnalyzedProperty.VERSION_CHANGE_TICKET, changeResult.getValue(), true);
        }
        putResult(report, AnalyzedProperty.ISSUES_TICKET, this.getIssuesTickets(), true);
        putResult(report, AnalyzedProperty.RESUMES_WITH_TICKET, this.getResumesWithTicket(), true);
        putResult(report, AnalyzedProperty.REPLAY_VULNERABLE_TICKET, this.getReplayVulnerable(), true);
        putResult(report, AnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET, this.getAllowsCiphersuiteChange(), true);

        writeToSiteReportVersionSpecific(report);
    }

    public abstract void writeToSiteReportVersionSpecific(SiteReport report);

    public List<Ticket> getTicketList() {
        return ticketList;
    }

    public void setTicketList(List<Ticket> ticketList) {
        this.ticketList = ticketList;
    }

    public TestResult getIssuesTickets() {
        return issuesTickets;
    }

    public void setIssuesTickets(TestResult issuesTickets) {
        this.issuesTickets = issuesTickets;
    }

    public TestResult getResumesWithTicket() {
        return resumesWithTicket;
    }

    public void setResumesWithTicket(TestResult resumesWithTicket) {
        this.resumesWithTicket = resumesWithTicket;
    }

    public TestResult getReplayVulnerable() {
        return replayVulnerable;
    }

    public void setReplayVulnerable(TestResult replayVulnerable) {
        this.replayVulnerable = replayVulnerable;
    }

    public TestResult getAllowsCiphersuiteChange() {
        return allowsCiphersuiteChange;
    }

    public void setAllowsCiphersuiteChange(TestResult allowsCiphersuiteChange) {
        this.allowsCiphersuiteChange = allowsCiphersuiteChange;
    }

    public Map<ProtocolVersion, TestResult> getVersionChangeResults() {
        return versionChangeResults;
    }

    public void setVersionChangeResult(ProtocolVersion version, TestResult result) {
        versionChangeResults.put(version, result);
    }
}
