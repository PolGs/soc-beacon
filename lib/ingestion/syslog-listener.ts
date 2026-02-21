import * as dgram from "dgram"
import * as net from "net"
import { parseSyslogMessage } from "./parser"
import { ingestLog } from "@/lib/pipeline"

interface SyslogListenerOptions {
  port: number
  protocol: "udp" | "tcp" | "both"
}

export class SyslogListener {
  private udpServer: dgram.Socket | null = null
  private tcpServer: net.Server | null = null
  private port: number
  private protocol: string
  private running = false

  constructor(options: SyslogListenerOptions) {
    this.port = options.port
    this.protocol = options.protocol
  }

  async start(): Promise<void> {
    if (this.running) return

    if (this.protocol === "udp" || this.protocol === "both") {
      await this.startUDP()
    }
    if (this.protocol === "tcp" || this.protocol === "both") {
      await this.startTCP()
    }

    this.running = true
    console.log(`[syslog] Listener started on port ${this.port} (${this.protocol})`)
  }

  private startUDP(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.udpServer = dgram.createSocket("udp4")

      this.udpServer.on("message", (msg) => {
        this.handleMessage(msg.toString("utf-8"))
      })

      this.udpServer.on("error", (err) => {
        console.error("[syslog] UDP error:", err.message)
        reject(err)
      })

      this.udpServer.bind(this.port, () => {
        console.log(`[syslog] UDP listening on port ${this.port}`)
        resolve()
      })
    })
  }

  private startTCP(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.tcpServer = net.createServer((socket) => {
        let buffer = ""
        socket.on("data", (data) => {
          buffer += data.toString("utf-8")
          const lines = buffer.split("\n")
          buffer = lines.pop() || ""
          for (const line of lines) {
            const trimmed = line.trim()
            if (trimmed) this.handleMessage(trimmed)
          }
        })
        socket.on("error", () => {
          // Client disconnect, ignore
        })
      })

      this.tcpServer.on("error", (err) => {
        console.error("[syslog] TCP error:", err.message)
        reject(err)
      })

      this.tcpServer.listen(this.port, () => {
        console.log(`[syslog] TCP listening on port ${this.port}`)
        resolve()
      })
    })
  }

  private handleMessage(raw: string) {
    try {
      const parsed = parseSyslogMessage(raw)
      ingestLog({
        timestamp: parsed.timestamp,
        source: parsed.source,
        message: parsed.message,
        severity: parsed.severity,
        parsed: true,
      }).catch((err) => {
        console.error("[syslog] Ingest error:", err.message)
      })
    } catch (err) {
      console.error("[syslog] Parse error:", err)
    }
  }

  async stop(): Promise<void> {
    if (!this.running) return

    if (this.udpServer) {
      this.udpServer.close()
      this.udpServer = null
    }
    if (this.tcpServer) {
      this.tcpServer.close()
      this.tcpServer = null
    }

    this.running = false
    console.log("[syslog] Listener stopped")
  }

  isRunning(): boolean {
    return this.running
  }
}
