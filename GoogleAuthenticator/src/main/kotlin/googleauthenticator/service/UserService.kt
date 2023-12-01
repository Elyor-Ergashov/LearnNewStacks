package googleauthenticator.service

import dev.turingcomplete.kotlinonetimepassword.GoogleAuthenticator
import googleauthenticator.domain.Permission
import googleauthenticator.domain.Role
import googleauthenticator.domain.User
import googleauthenticator.dtos.UserDto
import googleauthenticator.repository.UserRepository
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service


@Service
class UserService(
    private val userRepository: UserRepository,
    private val qrCodeService: QrCodeService,
    private val authenticatorService: AuthenticatorService
) {
    val passwordEncoder = BCryptPasswordEncoder()

    fun registerUser(userDto: UserDto): Long {
        val user = User(
            username = userDto.username,
            password = passwordEncoder.encode(userDto.password),
            role = userDto.role,
            authorities = setOf(Permission.MFA_REQUIRED.code)
        )
        val savedUser = userRepository.save(user)

        return savedUser.id!!
    }

    fun getUserById(id:Long): User {
        return userRepository.findById(id).get()

    }

    fun save(user: User): User {
        return userRepository.save(user)
    }

    fun getUserByUserName(username:String): User {
        return userRepository.findByUsername(username).get()

    }

    fun generateQrCodeImage(username: String): String {
        val qrCodeData = authenticatorService.generateQrCodeData(username)

        val user = getUserByUserName(username)
        user.secretKey  = qrCodeData.second
        save(user)

        return qrCodeService.generateQrCode(qrCodeData.first)
    }

    fun generateSecretKey(username: String): String {
        val secretKey = generateGoogleSecretKey()

        val user = getUserByUserName(username)
        user.secretKey  = secretKey
        save(user)

        return secretKey
    }

        fun generateGoogleSecretKey(): String {
        return GoogleAuthenticator.createRandomSecret()
    }
}


