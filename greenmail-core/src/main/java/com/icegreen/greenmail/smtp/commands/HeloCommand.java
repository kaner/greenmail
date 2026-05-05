/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.smtp.commands;

import com.icegreen.greenmail.smtp.SmtpConnection;
import com.icegreen.greenmail.smtp.SmtpManager;
import com.icegreen.greenmail.smtp.SmtpState;


/**
 * EHLO/HELO command.
 * <p>
 * TODO: What does HELO do if it's already been called before?
 * <p>
 * <a href="https://tools.ietf.org/html/rfc2821#section-4.1.1.1">RFC2821</a>
 * <a href="https://tools.ietf.org/html/rfc4954">RFC4954</a>
 * <a href="https://tools.ietf.org/html/rfc2554">RFC2554</a>
 */
public class HeloCommand
        extends SmtpCommand {
    @Override
    public void execute(SmtpConnection conn, SmtpState state,
                        SmtpManager manager, String commandLine) {
        boolean isExtended = commandLine.toUpperCase().startsWith("EHLO");
        extractHeloName(conn, commandLine);
        state.clearMessage();

        if (!isExtended) {
            // Plain HELO: single-line greeting, no extensions advertised.
            conn.send("250 " + conn.getServerGreetingsName());
            return;
        }

        conn.send("250-" + conn.getServerGreetingsName());
        if (conn.getServerSetup().isStartTlsEnabled() && !conn.isTlsActive()) {
            conn.send("250-STARTTLS");
        }
        conn.send("250 AUTH " + AuthCommand.SUPPORTED_AUTH_MECHANISM);
    }

    private void extractHeloName(SmtpConnection conn,
                                 String commandLine) {
        // Skip the keyword (HELO/EHLO) and following space, if any.
        int sp = commandLine.indexOf(' ');
        String heloName = (sp >= 0 && sp + 1 < commandLine.length()) ? commandLine.substring(sp + 1) : null;
        conn.setHeloName(heloName);
    }
}
