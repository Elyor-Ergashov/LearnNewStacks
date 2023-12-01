package googleauthenticator.extentions

import jakarta.servlet.http.HttpServletRequest
import org.json.JSONObject

fun HttpServletRequest.toJSON(): String {
    val jsonObject: JSONObject = JSONObject()
    jsonObject.put("Remote Address", this.remoteAddr)
    jsonObject.put("RequestURI", this.requestURI)
    jsonObject.put("Protocol", this.protocol)
    jsonObject.put("Remote host", this.remoteHost)
    jsonObject.put("Server Name", this.serverName)
    return jsonObject.toString()
}