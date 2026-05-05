/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 */
package com.icegreen.greenmail.pop3.commands;

import com.icegreen.greenmail.pop3.Pop3Connection;
import com.icegreen.greenmail.pop3.Pop3State;
import com.icegreen.greenmail.util.DummySSLServerSocketFactory;

import java.io.IOException;

/**
 * Handles the POP3 STLS command.
 * <p>
 * <a href="https://tools.ietf.org/html/rfc2595">RFC 2595</a>
 * <p>
 * Valid only in AUTHORIZATION state (i.e. before USER/PASS).
 */
public class StlsCommand extends Pop3Command {

    @Override
    public boolean isValidForState(Pop3State state) {
        return !state.isAuthenticated();
    }

    @Override
    public void execute(Pop3Connection conn, Pop3State state, String cmd) {
        if (!conn.getServerSetup().isStartTlsEnabled()) {
            conn.println("-ERR STLS not available");
            return;
        }
        if (conn.isTlsActive()) {
            conn.println("-ERR Command not permitted when TLS active");
            return;
        }

        conn.println("+OK Begin TLS negotiation");

        try {
            conn.upgradeToTls(
                ((DummySSLServerSocketFactory) DummySSLServerSocketFactory.getDefault()).getSSLContext());
            // RFC 2595 §4: discard any prior client knowledge after the upgrade.
            state.setUser(null);
        } catch (IOException e) {
            log.warn("STLS handshake failed", e);
            conn.quit();
        }
    }
}
