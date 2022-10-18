/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.core;

import static de.rub.nds.tlscrawler.core.Controller.shutdownSchedulerIfAllTriggersFinalized;

import org.quartz.*;

/**
 * Listener which shuts scheduler down when all triggers are finalized and thereby prevents application from running
 * forever if all schedules are finished.
 */
class SchedulerListenerShutdown implements SchedulerListener {

    private final Scheduler scheduler;

    SchedulerListenerShutdown(Scheduler scheduler) {
        this.scheduler = scheduler;
    }

    @Override
    public void jobScheduled(Trigger trigger) {
        shutdownSchedulerIfAllTriggersFinalized(scheduler);
    }

    @Override
    public void jobUnscheduled(TriggerKey triggerKey) {
        shutdownSchedulerIfAllTriggersFinalized(scheduler);
    }

    @Override
    public void triggerFinalized(Trigger trigger) {
        shutdownSchedulerIfAllTriggersFinalized(scheduler);
    }

    @Override
    public void triggerPaused(TriggerKey triggerKey) {
    }

    @Override
    public void triggersPaused(String triggerGroup) {
    }

    @Override
    public void triggerResumed(TriggerKey triggerKey) {
    }

    @Override
    public void triggersResumed(String triggerGroup) {
    }

    @Override
    public void jobAdded(JobDetail jobDetail) {
    }

    @Override
    public void jobDeleted(JobKey jobKey) {
    }

    @Override
    public void jobPaused(JobKey jobKey) {
    }

    @Override
    public void jobsPaused(String jobGroup) {
    }

    @Override
    public void jobResumed(JobKey jobKey) {
    }

    @Override
    public void jobsResumed(String jobGroup) {
    }

    @Override
    public void schedulerError(String msg, SchedulerException cause) {
    }

    @Override
    public void schedulerInStandbyMode() {
    }

    @Override
    public void schedulerStarted() {
    }

    @Override
    public void schedulerStarting() {
    }

    @Override
    public void schedulerShutdown() {
    }

    @Override
    public void schedulerShuttingdown() {
    }

    @Override
    public void schedulingDataCleared() {
    }
}