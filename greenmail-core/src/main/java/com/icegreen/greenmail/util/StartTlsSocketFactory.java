/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 */
package com.icegreen.greenmail.util;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.Socket;

/**
 * Helper for STARTTLS / STLS: wraps an established plain {@link Socket}
 * in a server-mode {@link SSLSocket} sharing the same {@link SSLContext}
 * (and therefore the same keystore / trust manager) used by
 * {@link DummySSLServerSocketFactory} for implicit-TLS server sockets.
 * <p>
 * NOT SECURE - intended for testing only. Anonymous cipher suites are enabled
 * to match the implicit-TLS server socket behavior.
 *
 * @see DummySSLServerSocketFactory
 */
public final class StartTlsSocketFactory {

    private StartTlsSocketFactory() {
        // utility
    }

    /**
     * Layer TLS over an existing plain socket and complete the handshake.
     * Caller must have already drained any client bytes that triggered the upgrade
     * (e.g. the {@code STARTTLS} / {@code STLS} command line and the server's
     * positive response) before calling this method.
     *
     * @param plain      the established plain socket; ownership transfers to the returned SSLSocket.
     * @param sslContext initialized SSLContext (typically obtained via
     *                   {@link DummySSLServerSocketFactory#getSSLContext()}).
     * @return a server-mode SSLSocket with handshake completed.
     * @throws IOException if the wrap or handshake fails.
     */
    public static SSLSocket upgrade(Socket plain, SSLContext sslContext) throws IOException {
        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) factory.createSocket(
            plain, plain.getInetAddress().getHostAddress(), plain.getPort(), true);
        sslSocket.setUseClientMode(false);
        // Match implicit-TLS server cipher coverage (DummySSLServerSocketFactory.addAnonCipher).
        sslSocket.setEnabledCipherSuites(
            DummySSLServerSocketFactory.addAnonCiphers(sslSocket.getEnabledCipherSuites()));
        sslSocket.startHandshake();
        return sslSocket;
    }
}
