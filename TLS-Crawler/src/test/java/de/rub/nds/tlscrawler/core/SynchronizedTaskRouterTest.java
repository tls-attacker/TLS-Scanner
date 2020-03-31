/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Class with tests for the SynchronizedTaskRouter implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SynchronizedTaskRouterTest {
    private SynchronizedTaskRouter subject;

    private ScanTask t0;
    private ScanTask t1;
    private ScanTask t2;
    private ScanTask t3;
    private ScanTask t4;

    private ScanTask t5;
    private ScanTask t6;
    private ScanTask t7;
    private ScanTask t8;
    private ScanTask t9;

    @Before
    public void setUp() {
        subject = new SynchronizedTaskRouter();

        t0 = mock(ScanTask.class);
        when(t0.getId()).thenReturn("0");
        t1 = mock(ScanTask.class);
        when(t1.getId()).thenReturn("1");
        t2 = mock(ScanTask.class);
        when(t2.getId()).thenReturn("2");
        t3 = mock(ScanTask.class);
        when(t3.getId()).thenReturn("3");
        t4 = mock(ScanTask.class);
        when(t4.getId()).thenReturn("4");
        t5 = mock(ScanTask.class);
        when(t5.getId()).thenReturn("5");
        t6 = mock(ScanTask.class);
        when(t6.getId()).thenReturn("6");
        t7 = mock(ScanTask.class);
        when(t7.getId()).thenReturn("7");
        t8 = mock(ScanTask.class);
        when(t8.getId()).thenReturn("8");
        t9 = mock(ScanTask.class);
        when(t9.getId()).thenReturn("9");

        subject.addTodo(t0);
        subject.addTodo(t1);
        subject.addTodo(t2);

        subject.addFinished(t7);
        subject.addFinished(t8);
        subject.addFinished(t9);
    }

    @Test
    public void getTodoCount() {
        SynchronizedTaskRouter tr = new SynchronizedTaskRouter();

        assertEquals(0, tr.getTodoCount());

        tr.addTodo(t1);

        assertEquals(1, tr.getTodoCount());

        tr.addTodo(t2);
        tr.addTodo(t3);
        tr.addTodo(t4);
        tr.addTodo(t5);
        tr.addTodo(t6);

        assertEquals(6, tr.getTodoCount());
    }

    @Test
    public void addTodo() {
        assertEquals(3, subject.getTodoCount());

        subject.addTodo(t3);

        assertEquals(4, subject.getTodoCount());

        subject.addTodo(t4);
        subject.addTodo(t5);
        subject.addTodo(t6);
        subject.addTodo(t7);

        assertEquals(8, subject.getTodoCount());
    }

    @Test
    public void addTodo_ListOverload() {
        assertEquals(3, subject.getTodoCount());

        subject.addTodo(Arrays.asList(t3, t4, t5));

        assertEquals(6, subject.getTodoCount());

        subject.addTodo(Arrays.asList(t6, t7, t8, t9));

        assertEquals(10, subject.getTodoCount());
    }

    @Test
    public void getTodo() {
        assertEquals(3, subject.getTodoCount());

        IScanTask task = subject.getTodo();

        assertTrue(Arrays.asList(t0, t1, t2).contains(task));
        assertEquals(2, subject.getTodoCount());

        subject.getTodo();
        subject.getTodo();

        assertEquals(0, subject.getTodoCount());

        subject.addTodo(t0);

        IScanTask st = subject.getTodo();

        assertEquals(t0, st);
        assertEquals(0, subject.getTodoCount());
    }

    @Test
    public void getFinishedCount() {
        assertEquals(3, subject.getFinishedCount());

        subject.addFinished(t0);

        assertEquals(4, subject.getFinishedCount());

        subject.getFinished();

        assertEquals(0, subject.getFinishedCount());
    }

    @Test
    public void addFinished() {
        assertEquals(3, subject.getFinishedCount());

        subject.addFinished(t0);

        assertEquals(4, subject.getFinishedCount());

        assertTrue(subject.getFinished().contains(t0));

        assertEquals(0, subject.getFinishedCount());

        subject.addFinished(t0);

        assertEquals(1, subject.getFinishedCount());

        subject.addFinished(t1);
        subject.addFinished(t2);

        assertEquals(3, subject.getFinishedCount());
    }

    @Test
    public void getFinished() {
        assertEquals(3, subject.getFinishedCount());

        subject.getFinished();

        assertEquals(0, subject.getFinishedCount());

        subject.addFinished(t0);

        assertEquals(1, subject.getFinishedCount());
        assertTrue(subject.getFinished().contains(t0));
        assertEquals(0, subject.getFinishedCount());

        subject.addFinished(t0);
        subject.addFinished(t1);
        subject.addFinished(t2);

        List lst = subject.getFinished();
        assertTrue(lst.contains(t0) && lst.contains(t1) && lst.contains(t2));
    }
}