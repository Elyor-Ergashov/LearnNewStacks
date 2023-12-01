package googleauthenticator.service

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil
import dev.turingcomplete.kotlinonetimepassword.GoogleAuthenticator
import org.springframework.stereotype.Service
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException


/**
 * Service class for providing authentication-related functionality.
 */
@Service
class AuthenticatorService {

    fun generateQrCodeData(username: String): Pair<String, String> {
        val issuer = "InterHUB"
        val label = URLEncoder.encode("$issuer:$username", StandardCharsets.UTF_8.toString())

        val secretKey = GoogleAuthenticator.createRandomSecret()
        val codeDigits = 6
        val period = 30

        val qrCodeData =  "otpauth://totp/$label?secret=$secretKey&issuer=$issuer&digits=$codeDigits&period=$period"
        return Pair(qrCodeData, secretKey)
    }

    fun check(secretKey: String, code: String): Boolean {
        return try {
            TimeBasedOneTimePasswordUtil.validateCurrentNumber(secretKey, code.toInt(), 10000)
        } catch (ex: IllegalArgumentException) {
            false
        } catch (ex: GeneralSecurityException) {
            throw IllegalArgumentException(ex)
        }
    }
}

