/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 */
package com.icegreen.greenmail.smtp.commands;

import com.icegreen.greenmail.smtp.SmtpConnection;
import com.icegreen.greenmail.smtp.SmtpManager;
import com.icegreen.greenmail.smtp.SmtpState;
import com.icegreen.greenmail.util.DummySSLServerSocketFactory;

import java.io.IOException;

/**
 * STARTTLS command.
 * <p>
 * <a href="https://tools.ietf.org/html/rfc3207">RFC 3207</a>
 */
public class StartTlsCommand extends SmtpCommand {

    @Override
    public void execute(SmtpConnection conn, SmtpState state,
                        SmtpManager manager, String commandLine) throws IOException {
        if (!conn.getServerSetup().isStartTlsEnabled()) {
            conn.send("502 STARTTLS not implemented");
            return;
        }
        if (conn.isTlsActive()) {
            conn.send("503 STARTTLS already active");
            return;
        }
        // RFC 3207: STARTTLS takes no parameters.
        if (commandLine.length() > "STARTTLS".length()) {
            conn.send("501 Syntax error (no parameters allowed)");
            return;
        }

        conn.send("220 Ready to start TLS");

        try {
            conn.upgradeToTls(
                ((DummySSLServerSocketFactory) DummySSLServerSocketFactory.getDefault()).getSSLContext());
        } catch (IOException ex) {
            log.warn("STARTTLS handshake failed", ex);
            conn.quit();
            return;
        }

        // RFC 3207 §4.2: server MUST discard any prior session state.
        conn.setHeloName(null);
        conn.setAuthenticated(false);
        state.clearMessage();
    }
}
