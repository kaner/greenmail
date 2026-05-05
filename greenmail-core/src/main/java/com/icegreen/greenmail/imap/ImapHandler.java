/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been modified by the copyright holder.
 * Original file can be found at http://james.apache.org
 */
package com.icegreen.greenmail.imap;

import com.icegreen.greenmail.server.AbstractSocketProtocolHandler;
import com.icegreen.greenmail.server.BuildInfo;
import com.icegreen.greenmail.user.UserManager;
import com.icegreen.greenmail.util.LoggingInputStream;
import com.icegreen.greenmail.util.LoggingOutputStream;
import com.icegreen.greenmail.util.ServerSetup;
import com.icegreen.greenmail.util.StartTlsSocketFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.Socket;

/**
 * The handler class for IMAP connections.
 *
 * @author Federico Barbieri &lt;scoobie@systemy.it&gt;
 * @author Peter M. Goldstein &lt;farsight@alum.mit.edu&gt;
 */
public class ImapHandler extends AbstractSocketProtocolHandler implements ImapConstants {
    private final ImapRequestHandler requestHandler = new ImapRequestHandler();
    private ImapSession session;

    private ImapResponse response;
    private InputStream ins;
    private OutputStream outs;
    private boolean tlsActive;
    private SSLSocket sslSocket;

    final UserManager userManager;
    private final ImapHostManager imapHost;
    private final ServerSetup serverSetup;

    public ImapHandler(UserManager userManager, ImapHostManager imapHost, Socket socket, ServerSetup serverSetup) {
        super(socket);
        this.userManager = userManager;
        this.imapHost = imapHost;
        this.serverSetup = serverSetup;
    }

    public ServerSetup getServerSetup() {
        return serverSetup;
    }

    public boolean isTlsActive() {
        return tlsActive;
    }

    /**
     * Layer TLS over the plain client socket and rebuild the IMAP I/O streams.
     * Per RFC 3501 §6.2.1 the client must send no further commands until the
     * handshake completes; the caller (STARTTLS command) is responsible for
     * issuing the tagged OK response and flushing it before invoking this.
     */
    public synchronized void upgradeToTls(SSLContext sslContext) throws IOException {
        sslSocket = StartTlsSocketFactory.upgrade(socket, sslContext);
        ins = wrapInput(sslSocket.getInputStream());
        outs = wrapOutput(sslSocket.getOutputStream());
        response = new ImapResponse(outs);
        tlsActive = true;
    }

    public void forceConnectionClose(final String message) {
        response.byeResponse(message);
        close();
    }

    @Override
    public void run() {
        try {
            ins = wrapInput(socket.getInputStream());
            outs = wrapOutput(socket.getOutputStream());
            response = new ImapResponse(outs);

            // Write welcome message
            String responseBuffer = VERSION + " Server GreenMail v" +
                    BuildInfo.INSTANCE.getProjectVersion() + " ready";
            response.okResponse(null, responseBuffer);

            session = new ImapSessionImpl(imapHost,
                    userManager,
                    this,
                    socket.getInetAddress().getHostAddress());

            // Re-read ins/outs from fields each iteration: STARTTLS swaps them.
            while (!isQuitting() && requestHandler.handleRequest(ins, outs, session)) {
                // Continue to handle requests
            }
        } catch (Exception e) {
            if (!isQuitting()) {
                throw new IllegalStateException("Can not handle IMAP connection", e);
            }
        } finally {
            close();
        }
    }

    private InputStream wrapInput(InputStream raw) {
        InputStream is = new BufferedInputStream(raw, 512);
        if (log.isDebugEnabled()) {
            is = new LoggingInputStream(is, "C: ");
        }
        return is;
    }

    private OutputStream wrapOutput(OutputStream raw) {
        OutputStream os = new BufferedOutputStream(raw, 1024);
        if (log.isDebugEnabled()) {
            os = new LoggingOutputStream(os, "S: ");
        }
        return os;
    }

    /**
     * Resets the handler data to a basic state.
     */
    @Override
    public void close() {
        // Close SSL socket first so close_notify reaches the client; autoClose=true
        // (see StartTlsSocketFactory.upgrade) cascade-closes the underlying plain
        // socket, which super.close() then skips via its isClosed() guard.
        if (sslSocket != null) {
            try {
                sslSocket.close();
            } catch (IOException e) {
                log.trace("Ignoring error closing SSL socket", e);
            }
        }
        super.close();

        // Clear user data
        session = null;
        response = null;
        ins = null;
        outs = null;
    }
}
