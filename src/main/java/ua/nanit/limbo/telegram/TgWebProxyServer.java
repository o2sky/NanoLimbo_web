/*
 * Telegram WebProxy - HTTP + WebSocket server (Netty), ported from
 * eooce/Telegram-webproxy nodejs/index.js. Runs alongside NanoLimbo.
 *
 * Routes:
 *   GET  /                -> bridge token page or stub html
 *   GET  /health          -> {"ok":true}
 *   POST /api/v1/session  -> bootstrap-auth, hello, creates session token
 *   DEL  /api/v1/session  -> delete session
 *   GET  /api/v1/ws       -> websocket lane upgrade (tproxy-lane-v1.TOKEN.SID)
 */
package ua.nanit.limbo.telegram;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.GlobalEventExecutor;
import ua.nanit.limbo.server.Log;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class TgWebProxyServer {

    public static final AttributeKey<TgSession> SESSION_KEY = AttributeKey.valueOf("tgp.session");
    public static final AttributeKey<Integer> LANE_SID = AttributeKey.valueOf("tgp.laneSid");
    public static final AttributeKey<String> LANE_TOKEN = AttributeKey.valueOf("tgp.laneToken");

    private final String secret;
    private final int port;
    private final byte[] secretKey;   // 32B derived key for MTProto cipher
    private final byte[] bootKey;     // HMAC key derived from boot

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;

    // session token -> lease
    final Map<String, Lease> leases = new ConcurrentHashMap<>();
    final ChannelGroup wsChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    public static class Lease {
        public final long expires;
        public final Map<Integer, Boolean> used = new ConcurrentHashMap<>();
        public volatile boolean deleted = false;

        Lease(String token) {
            long exp = 0;
            try {
                byte[] t = Base64.getUrlDecoder().decode(token);
                exp = ((t[0] & 0xFFL) << 24) | ((t[1] & 0xFFL) << 16)
                        | ((t[2] & 0xFFL) << 8) | (t[3] & 0xFFL);
            } catch (Exception ignored) {}
            this.expires = exp * 1000L;
        }
    }

    public TgWebProxyServer(String secret, int port) {
        this.secret = TgCrypto.normalizeSecret(secret);
        this.port = port;
        this.secretKey = TgCrypto.getKey(this.secret, false);
        this.bootKey = TgCrypto.hexToBytes(TgCrypto.deriveBoot(this.secret));
    }

    public byte[] bootKey() { return bootKey; }
    public byte[] secretKey() { return secretKey; }

    public void start() {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup(2);

        ServerBootstrap b = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(
                                new HttpServerCodec(),
                                new HttpObjectAggregator(2 * 1024 * 1024),
                                new TgHttpHandler(TgWebProxyServer.this));
                    }
                })
                .childOption(ChannelOption.TCP_NODELAY, true);

        try {
            serverChannel = b.bind(port).sync().channel();
            Log.info("[TG-WebProxy] listening on :" + port);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Log.error("[TG-WebProxy] bind failed", e);
        }
    }

    public void stop() {
        if (serverChannel != null) serverChannel.close();
        if (bossGroup != null) bossGroup.shutdownGracefully();
        if (workerGroup != null) workerGroup.shutdownGracefully();
        Log.info("[TG-WebProxy] stopped");
    }

    /**
     * Upgrades an HTTP request to a websocket lane. Returns true if handled.
     */
    public boolean handleUpgrade(ChannelHandlerContext ctx, FullHttpRequest req) {
        WebSocketServerHandshakerFactory factory =
                new WebSocketServerHandshakerFactory(getWsLocation(req), null, true, 4 * 1024 * 1024);
        WebSocketServerHandshaker handshaker = factory.newHandshaker(req);
        if (handshaker == null) {
            WebSocketServerHandshakerFactory.sendUnsupportedVersionResponse(ctx.channel());
            return true;
        }
        handshaker.handshake(ctx.channel(), req.retain());
        // Frame router: our own handshaker did the upgrade, so we must NOT add
        // WebSocketServerProtocolHandler — its internal HandshakeHandler casts
        // every inbound message to HttpObject and throws ClassCastException on
        // websocket frames. TgLaneHandler handles frames directly.
        TgLaneHandler lane = new TgLaneHandler(this);
        ctx.pipeline().addLast(lane);
        lane.onHandshake(req.headers().getAsString(io.netty.handler.codec.http.HttpHeaderNames.SEC_WEBSOCKET_PROTOCOL),
                ctx.channel());
        return true;
    }

    private String getWsLocation(FullHttpRequest req) {
        String host = req.headers().getAsString(HttpHeaderNames.HOST);
        return "ws://" + host + "/api/v1/ws";
    }

    public void broadcastToLanes(String token, int sid, byte[] data) {
        // deliver downstream frame to the ws lane with given sid
        for (Channel ch : wsChannels) {
            Integer chSid = ch.attr(LANE_SID).get();
            String chToken = ch.attr(LANE_TOKEN).get();
            if (chSid != null && chSid == sid && token.equals(chToken)) {
                ch.writeAndFlush(new BinaryWebSocketFrame(
                        Unpooled.wrappedBuffer(data)));
                return;
            }
        }
    }
}
