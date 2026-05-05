/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 */
package com.icegreen.greenmail.imap.commands;

import com.icegreen.greenmail.imap.ImapRequestLineReader;
import com.icegreen.greenmail.imap.ImapResponse;
import com.icegreen.greenmail.imap.ImapSession;
import com.icegreen.greenmail.imap.ProtocolException;

import java.io.IOException;

/**
 * Handles the IMAP STARTTLS command.
 * <p>
 * <a href="https://tools.ietf.org/html/rfc3501#section-6.2.1">RFC 3501 §6.2.1</a>
 * <a href="https://tools.ietf.org/html/rfc2595">RFC 2595</a>
 * <p>
 * Valid only in {@link com.icegreen.greenmail.imap.ImapSessionState#NON_AUTHENTICATED}.
 */
class StartTLSCommand extends NonAuthenticatedStateCommand {
    public static final String NAME = "STARTTLS";
    public static final String CAPABILITY = "STARTTLS";

    StartTLSCommand() {
        super(NAME, null);
    }

    @Override
    protected void doProcess(ImapRequestLineReader request,
                             ImapResponse response,
                             ImapSession session) throws ProtocolException {
        parser.endLine(request);

        if (!session.isStartTlsAvailable()) {
            response.commandFailed(this, "STARTTLS not available");
            return;
        }

        // Tagged OK precedes handshake (RFC 3501 §6.2.1).
        response.commandComplete(this);

        try {
            session.startTls();
        } catch (IOException e) {
            log.warn("STARTTLS handshake failed", e);
            session.closeConnection();
        }
    }
}
