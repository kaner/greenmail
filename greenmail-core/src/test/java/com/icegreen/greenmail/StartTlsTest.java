/*
 * Copyright (c) 2014 Wael Chatila / Icegreen Technologies. All Rights Reserved.
 * This software is released under the Apache license 2.0
 */
package com.icegreen.greenmail;

import com.icegreen.greenmail.junit.GreenMailRule;
import com.icegreen.greenmail.user.GreenMailUser;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.Retriever;
import com.icegreen.greenmail.util.ServerSetup;
import com.icegreen.greenmail.util.ServerSetupTest;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies STARTTLS / STLS support across SMTP, IMAP, and POP3 plain-port servers
 * configured via {@link ServerSetup#withStartTLS()}.
 */
public class StartTlsTest {

    private static final ServerSetup SMTP = ServerSetupTest.SMTP.withStartTLS();
    private static final ServerSetup IMAP = ServerSetupTest.IMAP.withStartTLS();
    private static final ServerSetup POP3 = ServerSetupTest.POP3.withStartTLS();

    @Rule
    public final GreenMailRule greenMail = new GreenMailRule(new ServerSetup[]{SMTP, IMAP, POP3});

    @Test
    public void smtpEhloAdvertisesStartTls() throws Exception {
        List<String> ehlo = ehloHandshake(SMTP);
        assertThat(ehlo).anySatisfy(line -> assertThat(line).contains("STARTTLS"));
    }

    @Test
    public void smtpStartTlsRejectedOnPlainSetupWithoutFlag() throws Exception {
        // Sanity: the standard plain SMTP setup (no withStartTLS()) must NOT advertise STARTTLS.
        // This preserves backwards compatibility for existing greenmail tests.
        ServerSetup plainOnly = ServerSetupTest.SMTP.port(SMTP.getPort() + 1000);
        try (Greenmail2 g = new Greenmail2(plainOnly)) {
            List<String> ehlo = ehloHandshake(plainOnly);
            assertThat(ehlo).noneSatisfy(line -> assertThat(line).contains("STARTTLS"));
        }
    }

    @Test
    public void smtpDeliveryViaStartTls() throws Exception {
        GreenMailUser user = greenMail.setUser("starttls-smtp@localhost", "starttls-smtp", "secret");

        Session session = greenMail.getSmtp().createSession();
        MimeMessage msg = new MimeMessage(session);
        msg.setFrom(new InternetAddress("from@localhost"));
        msg.setRecipients(Message.RecipientType.TO, "starttls-smtp@localhost");
        msg.setSubject("hello via starttls");
        msg.setText("body");
        Transport.send(msg, user.getLogin(), user.getPassword());

        greenMail.waitForIncomingEmail(5000, 1);
        MimeMessage[] received = greenMail.getReceivedMessages();
        assertThat(received).hasSize(1);
        assertThat(received[0].getSubject()).isEqualTo("hello via starttls");
    }

    @Test
    public void imapCapabilityAdvertisesStartTls() throws Exception {
        Store store = greenMail.getImap().createStore();
        // Use a fresh user; the connect drives CAPABILITY, STARTTLS, LOGIN.
        greenMail.setUser("imap-starttls@localhost", "imap-starttls", "secret");
        store.connect("imap-starttls", "secret");
        try {
            // Reaching connected state proves STARTTLS upgrade succeeded
            // (the session is configured with starttls.required=true).
            assertThat(store.isConnected()).isTrue();
            Folder inbox = store.getFolder("INBOX");
            inbox.open(Folder.READ_ONLY);
            inbox.close(false);
        } finally {
            store.close();
        }
    }

    @Test
    public void pop3StlsRawHandshake() throws Exception {
        // Speak POP3 manually: greeting, CAPA, STLS, then perform a TLS handshake
        // and a CAPA in cleartext-on-TLS. This isolates the server-side STLS path
        // from JavaMail's STARTTLS plumbing.
        try (Socket s = new Socket(POP3.getBindAddress(), POP3.getPort())) {
            InputStream rawIn = s.getInputStream();
            OutputStream rawOut = s.getOutputStream();

            String greeting = readPop3Line(rawIn);
            assertThat(greeting).startsWith("+OK");

            rawOut.write("CAPA\r\n".getBytes(StandardCharsets.US_ASCII));
            rawOut.flush();
            List<String> capa = readPop3MultiLine(rawIn);
            assertThat(capa).contains("STLS");

            rawOut.write("STLS\r\n".getBytes(StandardCharsets.US_ASCII));
            rawOut.flush();
            String stlsResponse = readPop3Line(rawIn);
            assertThat(stlsResponse).startsWith("+OK");

            // Wrap our client socket in an SSLSocket to drive the handshake.
            SSLContext clientCtx = SSLContext.getInstance("TLS");
            clientCtx.init(null, new TrustManager[]{new TrustAll()}, null);
            SSLSocketFactory clientFactory = clientCtx.getSocketFactory();
            try (SSLSocket sslClient = (SSLSocket) clientFactory.createSocket(s, s.getInetAddress().getHostAddress(), s.getPort(), false)) {
                sslClient.setUseClientMode(true);
                sslClient.startHandshake();

                // Talk POP3 over the now-encrypted channel.
                sslClient.getOutputStream().write("CAPA\r\n".getBytes(StandardCharsets.US_ASCII));
                sslClient.getOutputStream().flush();
                List<String> capaOnTls = readPop3MultiLine(sslClient.getInputStream());
                // After TLS, STLS should not be advertised any more.
                assertThat(capaOnTls).doesNotContain("STLS");
                assertThat(capaOnTls).contains("UIDL");

                sslClient.getOutputStream().write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
                sslClient.getOutputStream().flush();
            }
        }
    }

    @Test
    public void pop3DeliveryViaStls() throws Exception {
        // Drive the full POP3 STLS path via Angus Mail's POP3 client:
        // CAPA, STLS, handshake, USER/PASS, fetch INBOX.
        greenMail.setUser("pop3-stls@localhost", "pop3-stls", "secret");
        GreenMailUtil.sendTextEmail("pop3-stls@localhost", "from@localhost",
            "stls-subject", "stls-body", SMTP);
        greenMail.waitForIncomingEmail(5000, 1);

        try (Retriever retriever = new Retriever(greenMail.getPop3())) {
            Message[] messages = retriever.getMessages("pop3-stls", "secret");
            assertThat(messages).hasSize(1);
            assertThat(messages[0].getSubject()).isEqualTo("stls-subject");
        }
    }

    /**
     * Speak SMTP just far enough to issue EHLO and capture the multiline reply.
     * Quits cleanly without negotiating TLS. We are only inspecting the offered capabilities.
     */
    private static List<String> ehloHandshake(ServerSetup setup) throws Exception {
        try (Socket s = new Socket(setup.getBindAddress(), setup.getPort());
             BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
             PrintWriter out = new PrintWriter(s.getOutputStream(), false)) {
            readUntilCode(in, "220");
            out.print("EHLO test\r\n");
            out.flush();
            List<String> lines = readUntilCode(in, "250");
            out.print("QUIT\r\n");
            out.flush();
            return lines;
        }
    }

    /** Reads response lines until one starts with `code` followed by a space (final line of multi-line reply). */
    private static List<String> readUntilCode(BufferedReader in, String code) throws java.io.IOException {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = in.readLine()) != null) {
            lines.add(line);
            if (line.startsWith(code + " ")) {
                return lines;
            }
        }
        return lines;
    }

    private static String readPop3Line(InputStream in) throws java.io.IOException {
        StringBuilder sb = new StringBuilder();
        int prev = -1;
        while (true) {
            int b = in.read();
            if (b < 0) return sb.toString();
            if (prev == '\r' && b == '\n') {
                sb.setLength(sb.length() - 1);
                return sb.toString();
            }
            sb.append((char) b);
            prev = b;
        }
    }

    private static List<String> readPop3MultiLine(InputStream in) throws java.io.IOException {
        List<String> lines = new ArrayList<>();
        while (true) {
            String line = readPop3Line(in);
            if (".".equals(line)) break;
            if (line.isEmpty() && lines.isEmpty()) break; // shouldn't happen, defensive
            lines.add(line);
            if (line.startsWith("-ERR")) break;
        }
        return lines;
    }

    private static final class TrustAll implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    /** Tiny scoped helper to spin up a second SMTP server for the negative test. */
    private static final class Greenmail2 implements AutoCloseable {
        private final com.icegreen.greenmail.smtp.SmtpServer server;

        Greenmail2(ServerSetup setup) {
            com.icegreen.greenmail.Managers managers = new com.icegreen.greenmail.Managers();
            this.server = new com.icegreen.greenmail.smtp.SmtpServer(setup, managers);
            server.startService();
            try {
                if (!server.waitTillRunning(2000)) {
                    throw new IllegalStateException("Test SMTP server did not start");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void close() {
            server.stopService();
        }
    }
}
