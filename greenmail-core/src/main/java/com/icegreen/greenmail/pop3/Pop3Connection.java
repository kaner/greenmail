/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 * This file has been used and modified.
 * Original file can be found on http://foedus.sourceforge.net
 */
package com.icegreen.greenmail.pop3;

import com.icegreen.greenmail.foedus.util.StreamUtils;
import com.icegreen.greenmail.util.EncodingUtil;
import com.icegreen.greenmail.util.InternetPrintWriter;
import com.icegreen.greenmail.util.LoggingInputStream;
import com.icegreen.greenmail.util.LoggingOutputStream;
import com.icegreen.greenmail.util.ServerSetup;
import com.icegreen.greenmail.util.StartTlsSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;

public class Pop3Connection {
    // Logger.
    protected final Logger log = LoggerFactory.getLogger(getClass());
    // protocol stuff
    Pop3Handler handler;

    // networking stuff
    Socket socket;
    InetAddress clientAddress;

    // IO stuff
    BufferedInputStream in;
    InternetPrintWriter out;
    boolean tlsActive;
    SSLSocket sslSocket; // Non-null after a successful STLS upgrade; held so the handler can close it first to deliver close_notify.

    public Pop3Connection(Pop3Handler handler, Socket socket)
            throws IOException {
        configureSocket(socket);
        configureStreams();

        this.handler = handler;
    }

    private void configureStreams()
            throws IOException {
        // Output
        OutputStream o = socket.getOutputStream();
        if(log.isDebugEnabled()) {
            o = new LoggingOutputStream(o, "S: ");
        }
        out = InternetPrintWriter.createForEncoding(o, true, EncodingUtil.CHARSET_EIGHT_BIT_ENCODING);

        // Input: byte-level read so STLS upgrade is safe (a BufferedReader
        // backed by an InputStreamReader/StreamDecoder may pre-buffer bytes
        // beyond the line terminator).
        InputStream i = socket.getInputStream();
        if (log.isDebugEnabled()) {
            i = new LoggingInputStream(i, "C: ");
        }
        in = new BufferedInputStream(i);
    }

    private void configureSocket(Socket socket) {
        this.socket = socket;
        clientAddress = this.socket.getInetAddress();
    }

    public void close() throws IOException {
        socket.close();
    }

    public void quit() {
        handler.close();
    }

    public void println(String line) {
        out.print(line);
        println();
    }

    public void println() {
        out.print("\r\n");
        out.flush();
    }

    public void print(String line) {
        out.print(line);
    }

    public void print(Reader in) throws IOException {
        StreamUtils.copy(in, out);
        out.flush();
    }

    public void println(Reader in) throws IOException {
        StreamUtils.copy(in, out);
        println();
    }

    public String readLine() throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream(128);
        while (true) {
            int b = in.read();
            if (b < 0) {
                if (bos.size() == 0) {
                    return null;
                }
                return new String(bos.toByteArray(), java.nio.charset.StandardCharsets.US_ASCII);
            }
            if (b == '\r') {
                // Loop on consecutive CRs so CR-CR-LF terminates instead of hanging:
                // the second CR must be re-evaluated as a possible CRLF candidate.
                int next;
                while (true) {
                    next = in.read();
                    if (next == '\n') {
                        return new String(bos.toByteArray(), java.nio.charset.StandardCharsets.US_ASCII);
                    }
                    bos.write('\r');
                    if (next < 0) {
                        return new String(bos.toByteArray(), java.nio.charset.StandardCharsets.US_ASCII);
                    }
                    if (next != '\r') {
                        b = next;
                        break;
                    }
                }
            }
            bos.write(b);
        }
    }

    public String getClientAddress() {
        return clientAddress.toString();
    }

    public ServerSetup getServerSetup() {
        return handler.getServerSetup();
    }

    public boolean isTlsActive() {
        return tlsActive;
    }

    /**
     * @return the active SSLSocket if {@link #upgradeToTls(SSLContext)} ran, else {@code null}.
     */
    public SSLSocket getSslSocket() {
        return sslSocket;
    }

    /**
     * Layer TLS over the existing plain socket and replace this connection's streams.
     * Per RFC 2595 §4 the client MUST NOT pipeline any bytes after STLS, so the input
     * buffer is expected to be empty at this point.
     */
    public void upgradeToTls(SSLContext sslContext) throws IOException {
        SSLSocket newSslSocket = StartTlsSocketFactory.upgrade(socket, sslContext);
        this.socket = newSslSocket;
        this.sslSocket = newSslSocket;

        OutputStream o = newSslSocket.getOutputStream();
        if (log.isDebugEnabled()) {
            o = new LoggingOutputStream(o, "S: ");
        }
        out = InternetPrintWriter.createForEncoding(o, true, EncodingUtil.CHARSET_EIGHT_BIT_ENCODING);

        InputStream i = newSslSocket.getInputStream();
        if (log.isDebugEnabled()) {
            i = new LoggingInputStream(i, "C: ");
        }
        in = new BufferedInputStream(i);

        tlsActive = true;
    }
}
