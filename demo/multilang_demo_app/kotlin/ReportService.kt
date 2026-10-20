package demo.reports

import java.io.File
import java.sql.Connection
import org.springframework.web.bind.annotation.*

@RestController
class ReportService(private val conn: Connection) {
    private val apiKey = "sk_live_51HxYzExample"

    @GetMapping("/reports")
    fun reports(@RequestParam owner: String): List<String> {
        val rs = conn.createStatement().executeQuery("SELECT title FROM reports WHERE owner = '$owner'")
        val out = mutableListOf<String>()
        while (rs.next()) out.add(rs.getString(1))
        return out
    }

    @GetMapping("/reports/safe")
    fun reportsSafe(@RequestParam owner: String): List<String> {
        val st = conn.prepareStatement("SELECT title FROM reports WHERE owner = ?")
        st.setString(1, owner)
        val rs = st.executeQuery()
        val out = mutableListOf<String>()
        while (rs.next()) out.add(rs.getString(1))
        return out
    }

    @GetMapping("/download")
    fun download(@RequestParam name: String): ByteArray = File("/srv/reports/" + name).readBytes()

    @PostMapping("/tools/dig")
    fun dig(@RequestParam host: String): String {
        val p = Runtime.getRuntime().exec("dig " + host)
        return p.inputStream.bufferedReader().readText()
    }
}
