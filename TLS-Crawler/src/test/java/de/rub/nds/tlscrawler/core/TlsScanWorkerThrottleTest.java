/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** Unit tests for the per-scan-target write throttle in {@link TlsScanWorker#isUpdateAllowed}. */
public class TlsScanWorkerThrottleTest {

    private static final long THROTTLE_MS = 5000;

    @Test
    public void firstWriteIsAlwaysAllowed() {
        AtomicLong last = new AtomicLong(0L);
        // Even at t=0 the very first write must go through (last == 0 sentinel).
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, 0L));
        assertEquals(0L, last.get(), "last write time should be recorded as the supplied now");
    }

    @Test
    public void writeWithinWindowIsThrottled() {
        AtomicLong last = new AtomicLong(0L);
        long base = 1_000_000L;
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, base));
        assertFalse(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, base + 1));
        assertFalse(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, base + THROTTLE_MS - 1));
        // Throttled calls must not advance the last-write timestamp.
        assertEquals(base, last.get());
    }

    @Test
    public void writeAfterWindowIsAllowedAndAdvancesWindow() {
        AtomicLong last = new AtomicLong(0L);
        long base = 1_000_000L;
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, base));
        long afterWindow = base + THROTTLE_MS;
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, afterWindow));
        assertEquals(afterWindow, last.get());
        // The next window now starts at afterWindow.
        assertFalse(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, afterWindow + 1));
    }

    @Test
    public void nonPositiveThrottleDisablesThrottling() {
        AtomicLong last = new AtomicLong(0L);
        long base = 1_000_000L;
        for (long t = base; t < base + 10; t++) {
            assertTrue(
                    TlsScanWorker.isUpdateAllowed(0, last, t),
                    "throttleMs=0 must allow every write");
            assertTrue(
                    TlsScanWorker.isUpdateAllowed(-1, last, t),
                    "negative throttleMs must allow writes");
        }
    }

    @Test
    public void concurrentUpdatesAllowOnlyOneWritePerWindow() throws InterruptedException {
        AtomicLong last = new AtomicLong(0L);
        // Seed the window so the sentinel-first-write rule doesn't grant an extra pass.
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, 1L));

        int threads = 32;
        long now = 2L; // well within the THROTTLE_MS window opened at t=1
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger(0);
        for (int i = 0; i < threads; i++) {
            pool.submit(
                    () -> {
                        try {
                            start.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                        if (TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, now)) {
                            allowed.incrementAndGet();
                        }
                    });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(
                0,
                allowed.get(),
                "no concurrent update inside the open window should be allowed to write");
    }

    @Test
    public void concurrentUpdatesAtWindowEdgeAllowExactlyOne() throws InterruptedException {
        AtomicLong last = new AtomicLong(0L);
        assertTrue(TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, 1L));

        int threads = 32;
        long edge = 1L + THROTTLE_MS; // exactly when the window reopens
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger allowed = new AtomicInteger(0);
        for (int i = 0; i < threads; i++) {
            pool.submit(
                    () -> {
                        try {
                            start.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return;
                        }
                        if (TlsScanWorker.isUpdateAllowed(THROTTLE_MS, last, edge)) {
                            allowed.incrementAndGet();
                        }
                    });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(
                1,
                allowed.get(),
                "exactly one concurrent update should win the window edge via CAS");
    }
}
