package googleauthenticator.controllers

import googleauthenticator.domain.User
import googleauthenticator.service.AuthenticationStore
import googleauthenticator.service.UserService
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
@RequestMapping("/qrcode")
class QrCodeController(private val userService: UserService, private val authenticationStore: AuthenticationStore) {

    @PostMapping("/generate")
    fun generateQrCode(@RequestParam("setupMethod") setupMethod: String, model: Model): String {
        val authenticationToken = authenticationStore.get()

        val userDTO = authenticationToken?.principal as User
        val user = userService.getUserByUserName(userDTO.username)

        if (setupMethod == "qrCode") {

            val qrCode = userService.generateQrCodeImage(user.username)

            model.addAttribute("qrCode", qrCode)
            model.addAttribute("qrCodeSectionStyle", "display: block;")
            model.addAttribute("manualCodeSectionStyle", "display: none;")
        } else {
            val manualCode = userService.generateSecretKey(user.username)

            model.addAttribute("manualCode", manualCode)
            model.addAttribute("qrCodeSectionStyle", "display: none;")
            model.addAttribute("manualCodeSectionStyle", "display: block;")
        }

        return "qrcode"
    }

}
