package demo.web

import java.io.File
import java.security.MessageDigest
import javax.servlet.http.HttpServletRequest
import java.sql.Connection

class UserHandler(private val conn: Connection) {
    fun find(req: HttpServletRequest): Boolean {
        val id = req.getParameter("id")
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id)
        return true
    }

    fun run(req: HttpServletRequest) {
        val tool = req.getParameter("tool")
        Runtime.getRuntime().exec(tool)
    }

    fun read(req: HttpServletRequest): String {
        val name = req.getParameter("name")
        val text = File(name).readText()
        val safe = File("static/index.html").readText()
        return text + safe
    }

    fun hash(s: String): ByteArray {
        val md = MessageDigest.getInstance("MD5")
        return md.digest(s.toByteArray())
    }

    fun lambdas(req: HttpServletRequest) {
        val cmd = req.getParameter("c")
        val run = { c: String -> Runtime.getRuntime().exec(c) }
        run(cmd)
        listOf(cmd).forEach { Runtime.getRuntime().exec(it) }
        val safe = listOf("ls").map { it.trim() }
        safe.forEach { Runtime.getRuntime().exec(it) }
    }

    fun control(req: HttpServletRequest) {
        val input = readLine()
        val picked = if (input != null) input else "default"
        try {
            Runtime.getRuntime().exec(picked)
        } catch (e: Exception) {
            println(e)
        } finally {
            println("done")
        }
        when (picked) {
            "a" -> Runtime.getRuntime().exec(picked)
            else -> println(picked)
        }
        for (part in picked.split(",")) { Runtime.getRuntime().exec(part) }
    }
}

fun main(args: Array<String>) {
    println(args.size)
}

class Holder {
    private var last: String = ""

    fun remember(req: HttpServletRequest) {
        this.last = req.getParameter("v")
    }

    fun useLast() {
        Runtime.getRuntime().exec(last)
    }
}
