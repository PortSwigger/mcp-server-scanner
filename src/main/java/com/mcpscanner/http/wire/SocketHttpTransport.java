package com.mcpscanner.http.wire;

import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

public final class SocketHttpTransport {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final String HTTPS_IDENTIFICATION = "HTTPS";

    private final Duration readTimeout;
    private final Duration connectTimeout;
    private final SSLSocketFactory tls;

    public SocketHttpTransport(Duration readTimeout) {
        this(readTimeout, (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    public SocketHttpTransport(Duration readTimeout, SSLSocketFactory tls) {
        this(readTimeout, DEFAULT_CONNECT_TIMEOUT, tls);
    }

    SocketHttpTransport(Duration readTimeout, Duration connectTimeout, SSLSocketFactory tls) {
        this.readTimeout = readTimeout;
        this.connectTimeout = connectTimeout;
        this.tls = tls;
    }

    public WireExchange exchange(WireRequest request) throws IOException {
        Socket socket = connect(request);
        try {
            socket.setSoTimeout((int) readTimeout.toMillis());
            OutputStream out = socket.getOutputStream();
            out.write(request.bytes());
            out.flush();
            SocketTap tap = new SocketTap(request, new BufferedInputStream(
                    new DeadlineInputStream(socket, Instant.now().plus(readTimeout))));
            return new WireExchange(socket, WireResponse.read(tap.read(), request.method()), tap);
        } catch (IOException | RuntimeException failure) {
            socket.close();
            throw failure;
        }
    }

    private Socket connect(WireRequest request) throws UnsentRequestException {
        Socket plain = new Socket();
        SocketDeadline deadline = SocketDeadline.closing(plain, connectTimeout);
        try {
            Socket connected = connectWithin(plain, request);
            if (!deadline.disarm()) {
                throw new SocketTimeoutException("connect deadline passed");
            }
            return connected;
        } catch (IOException failure) {
            deadline.disarm();
            closeQuietly(plain);
            throw new UnsentRequestException(failure);
        } catch (RuntimeException failure) {
            deadline.disarm();
            closeQuietly(plain);
            throw new UnsentRequestException(new IOException(failure));
        }
    }

    private Socket connectWithin(Socket plain, WireRequest request) throws IOException {
        plain.connect(new InetSocketAddress(request.host(), request.port()), (int) connectTimeout.toMillis());
        return request.secure() ? handshake(plain, request) : plain;
    }

    private SSLSocket handshake(Socket plain, WireRequest request) throws IOException {
        SSLSocket secured = (SSLSocket) tls.createSocket(plain, request.host(), request.port(), true);
        SSLParameters parameters = secured.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm(HTTPS_IDENTIFICATION);
        List<SNIServerName> serverNames = SniServerNames.forHost(request.host());
        if (!serverNames.isEmpty()) {
            parameters.setServerNames(serverNames);
        }
        secured.setSSLParameters(parameters);
        secured.setSoTimeout((int) connectTimeout.toMillis());
        secured.startHandshake();
        return secured;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
