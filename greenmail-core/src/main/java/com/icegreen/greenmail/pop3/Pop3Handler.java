/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.pop3;

import com.icegreen.greenmail.pop3.commands.Pop3Command;
import com.icegreen.greenmail.pop3.commands.Pop3CommandRegistry;
import com.icegreen.greenmail.server.AbstractSocketProtocolHandler;
import com.icegreen.greenmail.server.BuildInfo;
import com.icegreen.greenmail.user.UserManager;
import com.icegreen.greenmail.util.ServerSetup;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.StringTokenizer;


public class Pop3Handler extends AbstractSocketProtocolHandler {
    final Pop3CommandRegistry registry;
    Pop3Connection conn;
    final UserManager manager;
    Pop3State state;
    String currentLine;
    private final ServerSetup serverSetup;

    public Pop3Handler(Pop3CommandRegistry registry,
                       UserManager manager, Socket socket, ServerSetup serverSetup) {
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
        // After STLS, close the SSL socket first so close_notify reaches the client;
        // autoClose=true (StartTlsSocketFactory.upgrade) cascade-closes the underlying
        // plain socket, which super.close() then skips via its isClosed() guard.
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
            conn = new Pop3Connection(this, socket);
            state = new Pop3State(manager);

            sendGreetings();

            while (!isQuitting()) {
                handleCommand();
            }

            conn.close();
        } catch (SocketTimeoutException ste) {
            conn.println("421 Service shutting down and closing transmission channel " +
                "(socket timeout, SO_TIMEOUT: " + getSoTimeout() + "ms)");
            conn.quit();
        } catch (Exception e) {
            if (!isQuitting()) {
                throw new IllegalStateException("Can not handle POP3 connection", e);
            }
        } finally {
            close();
        }
    }

    void sendGreetings() {
        conn.println("+OK POP3 GreenMail Server v" + BuildInfo.INSTANCE.getProjectVersion() + " ready");
    }

    void handleCommand() throws IOException {
        currentLine = conn.readLine();

        if (currentLine == null) {
            close();
            return;
        }

        String commandName = new StringTokenizer(currentLine, " ").nextToken().toUpperCase();
        Pop3Command command = registry.getCommand(commandName);

        if (command == null) {
            conn.println("-ERR Command not recognized");
            return;
        }

        if (!command.isValidForState(state)) {
            conn.println("-ERR Command not valid for this state");
            return;
        }

        command.execute(conn, state, currentLine);
    }
}
