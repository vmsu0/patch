const http = require("http");
const fs = require("fs");
const { spawn } = require("child_process");

// 读取 .env
function loadEnv(file) {
    const env = {};

    if (!fs.existsSync(file)) {
        return env;
    }

    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);

    for (const line of lines) {

        if (!line) continue;
        if (line.startsWith("#")) continue;

        const i = line.indexOf("=");

        if (i < 0) continue;

        const key = line.slice(0, i).trim();
        const value = line.slice(i + 1).trim();

        env[key] = value;
    }

    return env;
}

const env = loadEnv(".env");

const port = Number(env.ARGO_PORT || 8001);

const subUrl = env.SUB_URL;

const token = env.TOKEN || "";

let locked = false;
const waiting = [];

if (!subUrl) {
    console.error("SUB_URL is empty.");
    process.exit(1);
}

function handleRequest(req, res) {

    // Token 验证
    if (token && req.url !== "/" + token) {

        res.writeHead(403, {
            "Content-Type": "text/plain; charset=utf-8"
        });

        res.end("Forbidden");

        return;

    }

    // 并发锁
    if (locked) {

        waiting.push({ req, res });

        return;

    }

    locked = true;

    const curl = spawn("curl", [
        "-A",
        "Mozilla/5.0",
        subUrl
    ]);

    // 默认按文本返回订阅
    res.setHeader(
        "Content-Type",
        "text/plain; charset=utf-8"
    );

    // 原样返回 curl 输出
    curl.stdout.pipe(res);

    // 输出错误日志
    curl.stderr.on("data", data => {
        console.error(data.toString());
    });

    // curl 启动失败
    curl.on("error", err => {

        console.error(err);

        if (!res.headersSent) {

            res.writeHead(500, {
                "Content-Type": "text/plain; charset=utf-8"
            });

        }

        res.end(err.message);

    });

    // curl 退出异常
    curl.on("close", code => {

        if (code !== 0) {

            console.error(`curl exited: ${code}`);

        }

    // 释放并发锁
    locked = false;

    // 处理等待中的请求
    const next = waiting.shift();

    if (next) {

        handleRequest(next.req, next.res);

    }

    });

}

http.createServer(handleRequest).listen(port, () => {

    console.log(`Listening on ${port}`);

});
