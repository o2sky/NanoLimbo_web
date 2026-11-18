/*
 * Per-lane MTProto tunnel: decrypts client traffic, parses MTProto packets,
 * forwards to wss://kws{dc+1}[-1].web.telegram.org/apiws, encrypts the way back.
 */
package ua.nanit.limbo.telegram;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.util.concurrent.Promise;
import ua.nanit.limbo.server.Log;

import javax.net.ssl.SSLException;
import java.net.URI;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

public final class TgSession {

    private static final NioEventLoopGroup DC_GROUP = new NioEventLoopGroup(2);

    private final TgWebProxyServer server;
    private final Channel lane;
    private final int sid;
    private final byte[] secretKey;
    private final Runnable onClosed;

    private TgCrypto.CtrStream cIn;   // decrypt client -> plain
    private TgCrypto.CtrStream cOut;  // plain -> encrypt back to client
    private TgCrypto.CtrStream kOut;  // plain -> encrypt toward DC
    private TgCrypto.CtrStream kIn;   // decrypt from DC -> plain
    private TgCrypto.PktParser pkt;
    private volatile Channel dcChannel;
    private volatile boolean closed = false;
    private final ConcurrentLinkedQueue<byte[]> pendingUp = new ConcurrentLinkedQueue<>();
    private byte[] hdr = new byte[0];
    private final AtomicLong outWindow = new AtomicLong(4L * 1024 * 1024);

    TgSession(TgWebProxyServer server, Channel lane, int sid, byte[] secretKey, Runnable onClosed) {
        this.server = server;
        this.lane = lane;
        this.sid = sid;
        this.secretKey = secretKey;
        this.onClosed = onClosed;
    }

    void start() {
        // waits for the first data frame carrying the 64B fakeTLS head
    }

    void onClientData(byte[] data) {
        if (closed) return;
        try {
            for (TgCrypto.Frame f : TgCrypto.frames(data)) {
                if (f.sid != sid) throw new IllegalStateException("SID mismatch");
                switch (f.type) {
                    case 1: // open
                    case 2: // data
                        handleUp(f.payload);
                        break;
                    case 3: // end
                        close();
                        return;
                    case 4: // window grant
                        outWindow.addAndGet(TgCrypto.win(f.payload) & 0xFFFFFFFFL);
                        break;
                    default:
                        break;
                }
            }
        } catch (Exception e) {
            Log.debug("[TG-WebProxy] client frame error: " + e);
            close();
        }
    }

    private synchronized void handleUp(byte[] raw) {
        if (closed) return;
        try {
            if (cIn == null) {
                byte[] all = hdr.length == 0 ? raw : TgCrypto.concat(hdr, raw);
                if (all.length < 64) {
                    hdr = all;
                    return;
                }
                byte[] head = new byte[64];
                System.arraycopy(all, 0, head, 0, 64);
                byte[] rest = all.length > 64 ? new byte[all.length - 64] : new byte[0];
                if (all.length > 64) System.arraycopy(all, 64, rest, 0, rest.length);

                TgCrypto.Head info = TgCrypto.headOf(head);
                byte[] freshHead = TgCrypto.mkHead(info.mode, info.target, info.media);
                byte[][] wire = TgCrypto.wireHead(freshHead);
                byte[] wireHead = wire[0];

                byte[] inKey = TgCrypto.cipherKey(head, secretKey, false);
                byte[] inCtr = new byte[16];
                System.arraycopy(head, 40, inCtr, 0, 16);
                cIn = new TgCrypto.CtrStream(inKey, inCtr);

                byte[] outKey = TgCrypto.cipherKey(head, secretKey, true);
                byte[] outCtr = new byte[16];
                System.arraycopy(head, 40, outCtr, 0, 16);
                cOut = new TgCrypto.CtrStream(outKey, outCtr);

                kOut = new TgCrypto.CtrStream(wire[1], wire[2]);
                byte[] kInKey = TgCrypto.cipherKey(freshHead, secretKey, true);
                byte[] kInCtr = new byte[16];
                System.arraycopy(freshHead, 40, kInCtr, 0, 16);
                kIn = new TgCrypto.CtrStream(kInKey, kInCtr);

                pkt = new TgCrypto.PktParser(info.mode);
                connectDc(info.target, info.media, wireHead);
                if (rest.length > 0) upToDc(rest);
                return;
            }
            upToDc(raw);
        } catch (Exception e) {
            Log.debug("[TG-WebProxy] up error: " + e);
            close();
        }
    }

    private void upToDc(byte[] raw) {
        Channel dc = dcChannel;
        if (closed || dc == null || !dc.isActive()) {
            pendingUp.add(raw);
            return;
        }
        try {
            byte[] plain = cIn.crypt(raw);
            for (byte[] p : pkt.push(plain)) {
                byte[] w = kOut.crypt(p);
                dc.writeAndFlush(Unpooled.wrappedBuffer(w));
            }
        } catch (Exception e) {
            Log.debug("[TG-WebProxy] up parse error: " + e);
            close();
        }
    }

    private void connectDc(int target, boolean media, byte[] wireHead) {
        int dcNum = target + 1;
        String host = media ? ("kws" + dcNum + "-1.web.telegram.org")
                : ("kws" + dcNum + ".web.telegram.org");
        URI uri = URI.create("wss://" + host + "/apiws");

        SslContext ssl;
        try {
            ssl = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
        } catch (SSLException e) {
            Log.error("[TG-WebProxy] ssl ctx failed", e);
            close();
            return;
        }

        final SslContext sslCtx = ssl;
        final byte[] firstHead = wireHead;
        WebSocketClientHandshaker handshaker = WebSocketClientHandshakerFactory.newHandshaker(
                uri, WebSocketVersion.V13, "binary", true, new io.netty.handler.codec.http.DefaultHttpHeaders(), 4 * 1024 * 1024);
        final WebSocketClientHandshaker hs = handshaker;

        Promise<Channel> ready = dcChannel != null ? null : lane.eventLoop().newPromise();

        Bootstrap b = new Bootstrap()
                .group(DC_GROUP)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(
                                sslCtx.newHandler(ch.alloc(), host, 443),
                                new HttpClientCodec(),
                                new WebSocketClientProtocolHandler(hs, true, false),
                                new SimpleChannelInboundHandler<WebSocketFrame>() {
                                    @Override
                                    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
                                        if (evt == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                                            dcChannel = ctx.channel();
                                            // send re-obfuscated 64B head first
                                            ctx.writeAndFlush(new BinaryWebSocketFrame(
                                                    Unpooled.wrappedBuffer(firstHead)));
                                            byte[] q;
                                            while ((q = pendingUp.poll()) != null) upToDc(q);
                                        }
                                    }

                                    @Override
                                    protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) {
                                        if (frame instanceof BinaryWebSocketFrame) {
                                            byte[] d = new byte[frame.content().readableBytes()];
                                            frame.content().readBytes(d);
                                            onDcData(d);
                                        }
                                    }

                                    @Override
                                    public void channelInactive(ChannelHandlerContext ctx) {
                                        close();
                                    }

                                    @Override
                                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                        Log.debug("[TG-WebProxy] dc error: " + cause);
                                        close();
                                    }
                                });
                    }
                });

        b.connect(host, 443).addListener((ChannelFuture f) -> {
            if (!f.isSuccess()) {
                Log.debug("[TG-WebProxy] dc connect failed: " + f.cause());
                close();
            }
        });
    }

    private synchronized void onDcData(byte[] wire) {
        if (closed) return;
        try {
            byte[] plain = kIn.crypt(wire);
            byte[] raw = cOut.crypt(plain);
            sendDown(raw);
        } catch (Exception e) {
            Log.debug("[TG-WebProxy] dc data error: " + e);
            close();
        }
    }

    private void sendDown(byte[] data) {
        int chunk = 64 * 1024;
        for (int o = 0; o < data.length; o += chunk) {
            int n = Math.min(chunk, data.length - o);
            byte[] part = new byte[n];
            System.arraycopy(data, o, part, 0, n);
            byte[] frame = TgCrypto.encFrame(2, sid, part);
            lane.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(frame)));
        }
    }

    void close() {
        if (closed) return;
        closed = true;
        Channel dc = dcChannel;
        if (dc != null) dc.close();
        if (lane.isActive()) {
            lane.writeAndFlush(new BinaryWebSocketFrame(
                    Unpooled.wrappedBuffer(TgCrypto.encFrame(3, sid, new byte[0]))));
        }
        if (onClosed != null) onClosed.run();
    }
}
