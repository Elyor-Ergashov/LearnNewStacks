package googleauthenticator

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class GoogleAuthenticatorApplication

fun main(args: Array<String>) {
    runApplication<GoogleAuthenticatorApplication>(*args)
}
