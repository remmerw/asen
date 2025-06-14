package io.github.remmerw.asen.quic

internal class BadCertificateAlert(message: String?) :
    ErrorAlert(message, AlertDescription.BAD_CERTIFICATE)

internal class BadRecordMacAlert(message: String?) :
    ErrorAlert(message, AlertDescription.BAD_RECORD_MAC)

internal class DecryptErrorAlert(message: String?) :
    ErrorAlert(message, AlertDescription.DECRYPT_ERROR)

internal class HandshakeFailureAlert(message: String?) :
    ErrorAlert(message, AlertDescription.HANDSHAKE_FAILURE)

internal class IllegalParameterAlert(message: String?) :
    ErrorAlert(message, AlertDescription.ILLEGAL_PARAMETER)


internal class MissingExtensionAlert : ErrorAlert {
    constructor() : super("missing extension", AlertDescription.MISSING_EXTENSION)

    constructor(message: String?) : super(message, AlertDescription.MISSING_EXTENSION)
}

internal class UnexpectedMessageAlert(message: String?) :
    ErrorAlert(message, AlertDescription.UNEXPECTED_MESSAGE)

internal class UnsupportedExtensionAlert(message: String?) :
    ErrorAlert(message, AlertDescription.UNSUPPORTED_EXTENSION)

/**
 * Exception representing TLS error alert "decode_error".
 * See [...](https://www.davidwong.fr/tls13/#section-6.2)
 * "decode_error: A message could not be decoded because some field was out of the specified range or the length of
 * the message was incorrect. This alert is used for errors where the message does not conform to the formal
 * protocol syntax."
 */

internal class DecodeErrorException(message: String?) :
    ErrorAlert(message, AlertDescription.DECODE_ERROR)


internal abstract class ErrorAlert internal constructor(message: String?, alert: AlertDescription) :
    Exception(alert.name + "(" + alert.value() + ") " + message)