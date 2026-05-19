package protocol

import (
	"net/http"
	"strconv"
)

// Mode represents the protocol mode.
type Mode int

const (
	ModeHy Mode = iota
	ModeUz
)

const (
	URLPath = "/auth"

	StatusAuthOK = 233
)

// Hy mode constants
const (
	URLHost              = "hysteria"
	RequestHeaderAuth    = "Hysteria-Auth"
	ResponseHeaderUDPEnabled = "Hysteria-UDP"
	CommonHeaderCCRX     = "Hysteria-CC-RX"
	CommonHeaderPadding  = "Hysteria-Padding"
)

// Uz mode constants
const (
	URLHostUz               = "zivpnudp"
	RequestHeaderAuthUz        = "Zivpnudp-Auth"
	ResponseHeaderUDPEnabledUz = "Zivpnudp-UDP"
	CommonHeaderCCRXUz         = "Zivpnudp-CC-RX"
	CommonHeaderPaddingUz      = "Zivpnudp-Padding"
)

// AuthRequest is what client sends to server for authentication.
type AuthRequest struct {
	Auth string
	Rx   uint64 // 0 = unknown, client asks server to use bandwidth detection
}

// AuthResponse is what server sends to client when authentication is passed.
type AuthResponse struct {
	UDPEnabled bool
	Rx         uint64 // 0 = unlimited
	RxAuto     bool   // true = server asks client to use bandwidth detection
}

func authHeaderCCRX(mode Mode) string {
	if mode == ModeUz {
		return CommonHeaderCCRXUz
	}
	return CommonHeaderCCRX
}

func AuthRequestFromHeader(h http.Header, mode Mode) AuthRequest {
	ccHeader := authHeaderCCRX(mode)
	rx, _ := strconv.ParseUint(h.Get(ccHeader), 10, 64)
	authHeader := RequestHeaderAuth
	if mode == ModeUz {
		authHeader = RequestHeaderAuthUz
	}
	return AuthRequest{
		Auth: h.Get(authHeader),
		Rx:   rx,
	}
}

func AuthRequestToHeader(h http.Header, req AuthRequest, mode Mode) {
	authHeader := RequestHeaderAuth
	ccHeader := CommonHeaderCCRX
	padHeader := CommonHeaderPadding
	if mode == ModeUz {
		authHeader = RequestHeaderAuthUz
		ccHeader = CommonHeaderCCRXUz
		padHeader = CommonHeaderPaddingUz
	}
	h.Set(authHeader, req.Auth)
	h.Set(ccHeader, strconv.FormatUint(req.Rx, 10))
	h.Set(padHeader, authRequestPadding.String())
}

func AuthResponseFromHeader(h http.Header, mode Mode) AuthResponse {
	resp := AuthResponse{}
	udpHeader := ResponseHeaderUDPEnabled
	ccHeader := CommonHeaderCCRX
	if mode == ModeUz {
		udpHeader = ResponseHeaderUDPEnabledUz
		ccHeader = CommonHeaderCCRXUz
	}
	resp.UDPEnabled, _ = strconv.ParseBool(h.Get(udpHeader))
	rxStr := h.Get(ccHeader)
	if rxStr == "auto" {
		resp.RxAuto = true
	} else {
		resp.Rx, _ = strconv.ParseUint(rxStr, 10, 64)
	}
	return resp
}

func AuthResponseToHeader(h http.Header, resp AuthResponse, mode Mode) {
	udpHeader := ResponseHeaderUDPEnabled
	ccHeader := CommonHeaderCCRX
	padHeader := CommonHeaderPadding
	if mode == ModeUz {
		udpHeader = ResponseHeaderUDPEnabledUz
		ccHeader = CommonHeaderCCRXUz
		padHeader = CommonHeaderPaddingUz
	}
	h.Set(udpHeader, strconv.FormatBool(resp.UDPEnabled))
	if resp.RxAuto {
		h.Set(ccHeader, "auto")
	} else {
		h.Set(ccHeader, strconv.FormatUint(resp.Rx, 10))
	}
	h.Set(padHeader, authResponsePadding.String())
}
