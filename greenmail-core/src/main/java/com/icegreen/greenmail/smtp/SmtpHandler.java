/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.smtp;

import com.icegreen.greenmail.server.AbstractSocketProtocolHandler;
import com.icegreen.greenmail.server.BuildInfo;
import com.icegreen.greenmail.smtp.commands.SmtpCommand;
import com.icegreen.greenmail.smtp.commands.SmtpCommandRegistry;
import com.icegreen.greenmail.util.ServerSetup;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;

public class SmtpHandler extends AbstractSocketProtocolHandler {

    //RF821/2821 limit, extended for usage of XOAUTH2
    public static final int LINE_LENGHT_LIMIT = 4096;

    // protocol and configuration global stuff
    protected SmtpCommandRegistry registry;
    protected SmtpManager manager;
    protected final ServerSetup serverSetup;

    // session stuff
    protected SmtpConnection conn;
    protected SmtpState state;

    // command parsing stuff
    protected String currentLine;

    public SmtpHandler(SmtpCommandRegistry registry,
                       SmtpManager manager, Socket socket, ServerSetup serverSetup) {
        super(socket);
        this.registry = registry;
        this.manager = manager;
        this.serverSetup = serverSetup;
    }

    public ServerSetup getServerSetup() {
        return serverSetup;
    }

    @Override
    public void close() {
        // After STARTTLS, close the SSL socket first so close_notify reaches the
        // client; autoClose=true (StartTlsSocketFactory.upgrade) cascade-closes the
        // underlying plain socket, which super.close() then skips via isClosed().
        if (conn != null && conn.getSslSocket() != null) {
            try {
                conn.getSslSocket().close();
            } catch (IOException e) {
                log.trace("Ignoring error closing SSL socket", e);
            }
        }
        super.close();
    }

    @Override
    public void run() {
        try {
            conn = new SmtpConnection(this, socket);
            state = new SmtpState();

            sendGreetings();

            while (!isQuitting()) {
                handleCommand();
            }
        } catch (SocketTimeoutException ste) {
            conn.send("421 Service shutting down and closing transmission channel " +
                "(socket timeout, SO_TIMEOUT: " + getSoTimeout() + "ms)");
            conn.quit();
        } catch (Exception e) {
            // Closing socket on blocked read
            if (!isQuitting()) {
                throw new IllegalStateException("Unexpected error handling connection", e);
            }
        } finally {
            if (null != state) {
                state.clearMessage();
            }
            close();
        }
    }

    protected void sendGreetings() {
        conn.send("220 " + conn.getServerGreetingsName() +
            " GreenMail SMTP Service v" + BuildInfo.INSTANCE.getProjectVersion() + " ready");
    }

    protected void handleCommand()
        throws IOException {
        currentLine = conn.readLine();

        if (currentLine == null) {
            close();
            return;
        }

        if (currentLine.length() > LINE_LENGHT_LIMIT) {
            conn.send("500 Command too long.  " + LINE_LENGHT_LIMIT + " character maximum.");
            return;
        }

        // Extract command keyword: text up to first space, or the whole line if no space.
        int sp = currentLine.indexOf(' ');
        String commandName = (sp < 0 ? currentLine : currentLine.substring(0, sp)).toUpperCase();

        if (commandName.length() < 4) {
            conn.send("500 Invalid command. Must be at least 4 characters");
            return;
        }

        SmtpCommand command = registry.getCommand(commandName);

        if (command == null) {
            conn.send("500 Command not recognized");
            return;
        }

        command.execute(conn, state, manager, currentLine);
    }
}
