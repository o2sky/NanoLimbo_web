/*
 * HTTP routes for Telegram WebProxy (Netty).
 */
package ua.nanit.limbo.telegram;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import ua.nanit.limbo.server.Log;

import java.nio.charset.StandardCharsets;

public final class TgHttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private final TgWebProxyServer server;

    TgHttpHandler(TgWebProxyServer server) {
        // forward non-HTTP messages (websocket frames after upgrade) down the pipeline
        super(true);
        this.server = server;
    }

    private static void reply(ChannelHandlerContext ctx, HttpResponseStatus status,
                              String body, String contentType, boolean keepAlive) {
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status,
                Unpooled.wrappedBuffer(bytes));
        res.headers().set(HttpHeaderNames.CONTENT_LENGTH, bytes.length);
        if (contentType != null) res.headers().set(HttpHeaderNames.CONTENT_TYPE, contentType);
        res.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-store");
        res.headers().set("X-Content-Type-Options", "nosniff");
        ctx.writeAndFlush(res).addListener(ChannelFutureListener.CLOSE);
    }

    private static void replyEmpty(ChannelHandlerContext ctx, HttpResponseStatus status) {
        FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status);
        res.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);
        ctx.writeAndFlush(res).addListener(ChannelFutureListener.CLOSE);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
        HttpMethod method = req.method();
        String path = new QueryStringDecoder(req.uri()).path();

        // WebSocket upgrade
        if ("/api/v1/ws".equals(path) && method == HttpMethod.GET
                && "websocket".equalsIgnoreCase(req.headers().getAsString(HttpHeaderNames.UPGRADE))) {
            if (!server.handleUpgrade(ctx, req)) {
                replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
            }
            return;
        }

        if ("/health".equals(path) && method == HttpMethod.GET) {
            reply(ctx, HttpResponseStatus.OK, "{\"ok\":true}", "application/json; charset=utf-8", false);
            return;
        }

        if ("/".equals(path) && (method == HttpMethod.GET || method == HttpMethod.HEAD)) {
            reply(ctx, HttpResponseStatus.OK,
                    "<!doctype html><meta charset=\"utf-8\"><title>Connection</title>",
                    "text/html; charset=utf-8", false);
            return;
        }

        if ("/api/v1/session".equals(path)) {
            handleSession(ctx, req);
            return;
        }

        replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
    }

    private void handleSession(ChannelHandlerContext ctx, FullHttpRequest req) {
        HttpMethod method = req.method();
        String auth = bearer(req.headers().getAsString(HttpHeaderNames.AUTHORIZATION));

        if (method == HttpMethod.DELETE) {
            if (auth == null || !TgCrypto.verifyToken(auth, server.bootKey(), "session")) {
                replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
                return;
            }
            TgWebProxyServer.Lease lease = server.leases.get(auth);
            if (lease == null) {
                lease = new TgWebProxyServer.Lease(auth);
                server.leases.put(auth, lease);
            }
            lease.deleted = true;
            replyEmpty(ctx, HttpResponseStatus.NO_CONTENT);
            return;
        }

        if (method != HttpMethod.POST || auth == null) {
            replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
            return;
        }

        String contentType = req.headers().getAsString(HttpHeaderNames.CONTENT_TYPE);
        if (!"application/octet-stream".equals(contentType == null ? "" : contentType.trim())) {
            replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
            return;
        }

        // bootstrap token OR a valid session token
        boolean ok = auth.equals(TgCrypto.bytesToHex(server.bootKey()))
                || TgCrypto.verifyToken(auth, server.bootKey(), "bootstrap")
                || TgCrypto.verifyToken(auth, server.bootKey(), "session");
        if (!ok) {
            replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
            return;
        }

        byte[] body = new byte[req.content().readableBytes()];
        req.content().readBytes(body);
        try {
            TgCrypto.hello(body);
        } catch (Exception e) {
            replyEmpty(ctx, HttpResponseStatus.NOT_FOUND);
            return;
        }

        String token = TgCrypto.mkToken(server.bootKey(), "session",
                System.currentTimeMillis() + 5 * 60 * 1000);
        server.leases.put(token, new TgWebProxyServer.Lease(token));

        byte[] welcome = TgCrypto.encFrame(0x11, 0, new byte[0]);
        FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                Unpooled.wrappedBuffer(welcome));
        res.headers().set(HttpHeaderNames.CONTENT_LENGTH, welcome.length);
        res.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
        res.headers().set("X-Session-Token", token);
        res.headers().set("X-Carrier-Mode", "websocket-lanes");
        res.headers().set(HttpHeaderNames.CACHE_CONTROL, "no-store");
        ctx.writeAndFlush(res).addListener(ChannelFutureListener.CLOSE);
    }

    private static String bearer(String header) {
        if (header == null) return null;
        if (header.startsWith("Bearer ")) return header.substring(7).trim();
        return null;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Log.debug("[TG-WebProxy] http error: " + cause);
        ctx.close();
    }
}
