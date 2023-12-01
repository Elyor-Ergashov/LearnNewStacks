package googleauthenticator.service

import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import org.springframework.stereotype.Service
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Base64
import javax.imageio.ImageIO

@Service
class QrCodeService {

    @Throws(WriterException::class, IOException::class)
    fun generateQrCode(data: String): String {
        val bitMatrix: BitMatrix = MultiFormatWriter().encode(
            data,
            BarcodeFormat.QR_CODE,
            QR_CODE_WIDTH,
            QR_CODE_HEIGHT
        )

        val image = toBufferedImage(bitMatrix)
        val byteArrayOutputStream = ByteArrayOutputStream()

        ImageIO.write(image, "png", byteArrayOutputStream)
        val encodedImage = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray())

        return "data:image/png;base64,$encodedImage"
    }

    private fun toBufferedImage(matrix: BitMatrix): BufferedImage {
        val width = matrix.width
        val height = matrix.height
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)

        for (x in 0 until width) {
            for (y in 0 until height) {
                image.setRGB(x, y, if (matrix[x, y]) BLACK else WHITE)
            }
        }

        return image
    }

    companion object {
        private const val QR_CODE_WIDTH = 300
        private const val QR_CODE_HEIGHT = 300
        private const val BLACK = -0x1000000
        private const val WHITE = -0x1
    }
}

