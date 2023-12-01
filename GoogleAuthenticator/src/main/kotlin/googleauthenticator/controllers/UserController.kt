package googleauthenticator.controllers

import googleauthenticator.domain.User
import googleauthenticator.dtos.UserDto
import googleauthenticator.service.AuthenticationStore
import googleauthenticator.service.UserService
import jakarta.validation.Valid
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*


@Controller
@RequestMapping("/register")
class UserController(private val userService: UserService, private val authenticationStore: AuthenticationStore) {

    /**
     * Displays the registration form.
     * @param model the model to be used for rendering the view.
     * @return the name of the registration view template.
     */
    @GetMapping
    fun showRegistrationForm(model: Model): String {
        model.addAttribute("userDto", User())  // Add this line to initialize userDto in the model
        return "register"
    }

    /**
     * Handles the registration form submission.
     * @param userDto the user data submitted through the form.
     * @return a redirect to the registration success page.
     */
    @PostMapping
    fun registerUser(@ModelAttribute("userDto") @Valid userDto: UserDto): String {
        val userId = userService.registerUser(userDto)
        return "redirect:/register/success?userId=$userId"
    }

    /**
     * Displays the registration success page.
     * @param userId the ID of the registered user.
     * @param model the model to be used for rendering the view.
     * @return the name of the registration success view template.
     */
    @GetMapping("/success")
    fun registrationSuccess(@RequestParam userId: Long?, model: Model): String {
        model.addAttribute("userId", userId)
        return "redirect:/register/qrcode/$userId"
    }

    @GetMapping("/qrcode/{userId}")
    fun showQrCode(@PathVariable userId: Long, model: Model): String {
        val user = userService.getUserById(userId)

        val authenticationToken = UsernamePasswordAuthenticationToken(user, null, null)
        SecurityContextHolder.getContext().authentication = authenticationToken

        authenticationStore.save(authenticationToken)

        model.addAttribute("userId", userId)
        model.addAttribute("secretKey", user.secretKey)

        return "qrcode"
    }

}

