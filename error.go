package clocklock

import (
	"errors"
	"strconv"
)

var (
	ErrInvalidPEMBlock       = errors.New("Invalid PEM Block.")
	ErrInvalidCertificatePEM = errors.New("Invalid Certificate")
	ErrInvalidPublicPEM      = errors.New("Invalid Public Key")
	ErrInvalidRuleId         = errors.New("Invaid Rule ID.")
	ErrInvalidCertificateId  = errors.New("Invaid Certificate / Public Key ID.")
	ErrInvalidNonce          = errors.New("Invalid Nonce")
	ErrInvalidSignature      = errors.New("Invalid Signature")
	ErrMismatchedHash        = errors.New("Mismatched Hash Digest")
)

var (
	ErrorCodeUnknownError    = &ErrorCode{0, "Unknown Error"}
	ErrorCodeInvalidRequest  = &ErrorCode{1, "Invalid Request"}
	ErrorCodeServerError     = &ErrorCode{2, "Server Error"}
	ErrorCodeUnsupportedHash = &ErrorCode{3, "Unsupported Hash Algorithm"}
	ErrorCodeBadDigestLength = &ErrorCode{4, "Bad Digest Length for given Hash Algorithm"}
	ErrorCodeStampTimeout    = &ErrorCode{5, "Stamp Timeout"}
	ErrorCodeRequestTimeout  = &ErrorCode{6, "Request Timeout"}
	ErrorCodeAccuracy        = &ErrorCode{7, "Accuracy Error"}
	ErrorBadRule             = &ErrorCode{7, "Unacceptable Rule"}
	ErrorBadCert             = &ErrorCode{7, "Unacceptable Cert"}
	ErrorRuleUpdated         = &ErrorCode{7, "Rule Updated"}
)

type ResponseError struct {
	*ErrorCode
	Message error `json:message` // Any additional information about this error
}

func NewResponseError(code *ErrorCode, err error) *ResponseError {
	return &ResponseError{ErrorCode: code, Message: err}
}

func (err *ResponseError) Error() string {
	if err.Message != nil {
		return err.ErrorCode.Error() + ". " + err.Message.Error()
	} else {
		return err.ErrorCode.Error()
	}
}

type ErrorCode struct {
	Code int    `json:code`
	Err  string `json:error`
}

func (err *ErrorCode) Error() string {
	return "Error " + strconv.Itoa(err.Code) + ": " + err.Err
}
