/*
 * WebSocket lane handler: one lane = one ws connection carrying MTProto frames
 * for a single session stream. Bridges client <-> telegram DC over wss.
 *
 * Wiring note: TgHttpHandler completes the HTTP upgrade itself (via
 * WebSocketServerHandshaker) and then appends this handler to the pipeline.
 * Consequently no WebSocketServerProtocolHandler is present here — its
 * internal HandshakeHandler casts every inbound message to HttpObject and
 * throws ClassCastException on raw websocket frames. The subprotocol header
 * (tproxy-lane-v1.TOKEN.SID) is read directly from the upgrade request.
 */
package ua.nanit.limbo.telegram;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import ua.nanit.limbo.server.Log;

public final class TgLaneHandler extends SimpleChannelInboundHandler<BinaryWebSocketFrame> {

    private final TgWebProxyServer server;

    public TgLaneHandler(TgWebProxyServer server) {
        // keep non-matching messages flowing (binary frames are auto-released)
        super(true);
        this.server = server;
    }

    /**
     * Called by TgWebProxyServer/TgHttpHandler right after the upgrade
     * handshake, with the raw Sec-WebSocket-Protocol header from the request.
     */
    public void onHandshake(String proto, Channel ch) {
        // subprotocol: tproxy-lane-v1.TOKEN.SID
        String p = proto == null ? "" : proto;
        String[] parts = p.split("\\.");
        boolean ok = parts.length == 3 && "tproxy-lane-v1".equals(parts[0])
                && parts[2].matches("^[1-9][0-9]{0,7}$")
                && TgCrypto.verifyToken(parts[1], server.bootKey(), "session");
        if (!ok) {
            Log.debug("[TG-WebProxy] lane auth failed");
            ch.close();
            return;
        }
        int sid = Integer.parseInt(parts[2]);
        if (sid > 0xffffff) {
            ch.close();
            return;
        }
        TgWebProxyServer.Lease lease = server.leases.get(parts[1]);
        long now = System.currentTimeMillis();
        if (lease != null && lease.expires <= now && lease.used.isEmpty()) {
            server.leases.remove(parts[1]);
            lease = null;
        }
        if (lease == null) {
            if (server.leases.size() >= 4096) {
                ch.close();
                return;
            }
            lease = new TgWebProxyServer.Lease(parts[1]);
            server.leases.put(parts[1], lease);
        }
        if (lease.deleted || lease.used.containsKey(sid) || lease.used.size() >= 4096) {
            ch.close();
            return;
        }
        lease.used.put(sid, true);

        ch.attr(TgWebProxyServer.LANE_TOKEN).set(parts[1]);
        ch.attr(TgWebProxyServer.LANE_SID).set(sid);
        server.wsChannels.add(ch);

        final TgWebProxyServer.Lease fLease = lease;
        TgSession session = new TgSession(server, ch, sid,
                server.secretKey(), () -> {
            fLease.used.remove(sid);
            server.wsChannels.remove(ch);
        });
        ch.attr(TgWebProxyServer.SESSION_KEY).set(session);
        session.start();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, BinaryWebSocketFrame frame) {
        TgSession session = ctx.channel().attr(TgWebProxyServer.SESSION_KEY).get();
        if (session == null) return;
        byte[] data = new byte[frame.content().readableBytes()];
        frame.content().readBytes(data);
        session.onClientData(data);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        TgSession session = ctx.channel().attr(TgWebProxyServer.SESSION_KEY).get();
        if (session != null) session.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Log.debug("[TG-WebProxy] lane error: " + cause);
        TgSession session = ctx.channel().attr(TgWebProxyServer.SESSION_KEY).get();
        if (session != null) session.close();
        ctx.close();
    }
}
