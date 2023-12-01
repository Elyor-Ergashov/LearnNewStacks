package googleauthenticator.controllers

import googleauthenticator.configs.security.MultiFactorAuthentication
import googleauthenticator.service.AuthenticationStore
import googleauthenticator.service.AuthenticatorService
import googleauthenticator.service.UserService
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import java.io.IOException


@Controller
class LoginController(
    private val userService: UserService,
    private val authenticatorService: AuthenticatorService,
    private val authenticationStore: AuthenticationStore
) {

    private val securityContextRepository: SecurityContextRepository = HttpSessionSecurityContextRepository()
    private val authenticatorFailureHandler: AuthenticationFailureHandler =
        SimpleUrlAuthenticationFailureHandler("/authenticator?error")

    @GetMapping("/login")
    fun login(): String {
        return "login"
    }


    @GetMapping("/authenticator")
    fun authenticator(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication?
    ): String {

        val securityContext = SecurityContextHolder.getContext()
        val authenticationToken = authenticationStore.get()

        securityContext.authentication = authenticationToken
        SecurityContextHolder.setContext(securityContext)
        securityContextRepository.saveContext(securityContext, request, response)
        return "authenticator"
    }

    @PostMapping("/authenticator")
    @Throws(ServletException::class, IOException::class)
    fun validateCode(
        @RequestParam("code") code: String,
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: MultiFactorAuthentication?
    ): String {
        val authenticationToken = authenticationStore.get()

            val user = userService.getUserByUserName(authenticationToken!!.principal.toString())
            if (authenticatorService.check(user.secretKey, code)) {
                val securityContext = SecurityContextHolder.createEmptyContext()
                securityContext.authentication = authenticationToken
                SecurityContextHolder.setContext(securityContext)
                return "qrcode"
            }
        authenticatorFailureHandler.onAuthenticationFailure(
            request,
            response,
            BadCredentialsException("bad credentials")
        )
        return "authenticator"
    }

}
