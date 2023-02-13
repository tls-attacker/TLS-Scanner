/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.ScannerDetail;

public abstract class ReportPrinter<Report extends ScanReport> {

    protected final ScannerDetail detail;
    private int depth;

    private final PrintingScheme scheme;
    protected final boolean printColorful;

    protected final Report report;

    public ReportPrinter(
            ScannerDetail detail, PrintingScheme scheme, boolean printColorful, Report scanReport) {
        this.detail = detail;
        this.scheme = scheme;
        this.printColorful = printColorful;
        this.report = scanReport;
    }

    public abstract String getFullReport();

    protected String getBlackString(String value, String format) {
        return String.format(format, value == null ? "Unknown" : value);
    }

    protected String getGreenString(String value, String format) {
        return (printColorful ? AnsiColor.GREEN.getCode() : AnsiColor.RESET.getCode())
                + String.format(format, value == null ? "Unknown" : value)
                + AnsiColor.RESET.getCode();
    }

    protected String getYellowString(String value, String format) {
        return (printColorful ? AnsiColor.YELLOW.getCode() : AnsiColor.RESET.getCode())
                + String.format(format, value == null ? "Unknown" : value)
                + AnsiColor.RESET.getCode();
    }

    protected String getRedString(String value, String format) {
        return (printColorful ? AnsiColor.RED.getCode() : AnsiColor.RESET.getCode())
                + String.format(format, value == null ? "Unknown" : value)
                + AnsiColor.RESET.getCode();
    }

    protected StringBuilder prettyAppend(StringBuilder builder, String value) {
        return builder.append(value == null ? "Unknown" : value).append("\n");
    }

    protected StringBuilder prettyAppend(StringBuilder builder, String value, AnsiColor color) {
        if (printColorful) {
            builder.append(color.getCode());
        }
        builder.append(value);
        if (printColorful) {
            builder.append(AnsiColor.RESET.getCode());
        }
        builder.append("\n");
        return builder;
    }

    protected StringBuilder prettyAppend(StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(value == null ? "Unknown" : value)
                .append("\n");
    }

    protected StringBuilder prettyAppend(StringBuilder builder, String name, Long value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(value == null ? "Unknown" : value)
                .append("\n");
    }

    protected StringBuilder prettyAppend(StringBuilder builder, String name, Boolean value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(value == null ? "Unknown" : value)
                .append("\n");
    }

    protected StringBuilder prettyAppend(
            StringBuilder builder, String name, AnalyzedProperty property) {
        builder.append(addIndentations(name)).append(": ");
        builder.append(scheme.getEncodedString(report, property, printColorful));
        builder.append("\n");
        return builder;
    }

    protected StringBuilder prettyAppend(
            StringBuilder builder, String name, Boolean value, AnsiColor color) {
        return prettyAppend(builder, name, "" + value, color);
    }

    protected StringBuilder prettyAppend(
            StringBuilder builder, String name, String value, AnsiColor color) {
        builder.append(addIndentations(name)).append(": ");
        if (printColorful) {
            builder.append(color.getCode());
        }
        builder.append(value);
        if (printColorful) {
            builder.append(AnsiColor.RESET.getCode());
        }
        builder.append("\n");
        return builder;
    }

    protected StringBuilder prettyAppendHeading(StringBuilder builder, String value) {
        depth = 0;

        return builder.append(
                        printColorful
                                ? AnsiColor.BOLD.getCode() + AnsiColor.BLUE.getCode()
                                : AnsiColor.RESET.getCode())
                .append("\n------------------------------------------------------------\n")
                .append(value)
                .append("\n\n")
                .append(AnsiColor.RESET.getCode());
    }

    protected StringBuilder prettyAppendUnderlined(
            StringBuilder builder, String name, String value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(
                        (printColorful
                                ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode()
                                : value))
                .append("\n");
    }

    protected StringBuilder prettyAppendUnderlined(
            StringBuilder builder, String name, boolean value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(
                        (printColorful
                                ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode()
                                : value))
                .append("\n");
    }

    protected StringBuilder prettyAppendUnderlined(StringBuilder builder, String name, long value) {
        return builder.append(addIndentations(name))
                .append(": ")
                .append(
                        (printColorful == false
                                ? AnsiColor.UNDERLINE.getCode() + value + AnsiColor.RESET.getCode()
                                : value))
                .append("\n");
    }

    protected StringBuilder prettyAppendSubheading(StringBuilder builder, String name) {
        depth = 1;
        return builder.append("--|")
                .append(
                        printColorful
                                ? AnsiColor.BOLD.getCode()
                                        + AnsiColor.PURPLE.getCode()
                                        + AnsiColor.UNDERLINE.getCode()
                                        + name
                                        + "\n\n"
                                        + AnsiColor.RESET.getCode()
                                : name + "\n\n");
    }

    protected StringBuilder prettyAppendSubSubheading(StringBuilder builder, String name) {
        depth = 2;
        return builder.append("----|")
                .append(
                        printColorful
                                ? AnsiColor.BOLD.getCode()
                                        + AnsiColor.PURPLE.getCode()
                                        + AnsiColor.UNDERLINE.getCode()
                                        + name
                                        + "\n\n"
                                        + AnsiColor.RESET.getCode()
                                : name + "\n\n");
    }

    protected StringBuilder prettyAppendSubSubSubheading(StringBuilder builder, String name) {
        depth = 3;
        return builder.append("------|")
                .append(
                        printColorful
                                ? AnsiColor.BOLD.getCode()
                                        + AnsiColor.PURPLE.getCode()
                                        + AnsiColor.UNDERLINE.getCode()
                                        + name
                                        + "\n\n"
                                        + AnsiColor.RESET.getCode()
                                : name + "\n\n");
    }

    protected String padToLength(String value, int length) {
        StringBuilder builder = new StringBuilder(value);
        while (builder.length() < length) {
            builder.append(" ");
        }
        return builder.toString();
    }

    protected String addIndentations(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            builder.append(" ");
        }
        builder.append(value);
        if (value.length() + depth < 8) {
            builder.append("\t\t\t\t ");
        } else if (value.length() + depth < 16) {
            builder.append("\t\t\t ");
        } else if (value.length() + depth < 24) {
            builder.append("\t\t ");
        } else if (value.length() + depth < 32) {
            builder.append("\t ");
        } else {
            builder.append(" ");
        }
        return builder.toString();
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }
}
