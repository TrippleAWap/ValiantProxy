package main

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"ValiantProxy/gophertunnel/minecraft/protocol/login"
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
)

var (
	expectedProtocol int32 = 800
	defaultCheckCode int   = 0xFFFF | 20210701
	checkCodes       []int

	checks = []string{
		"CPNS", // "client protocol not supported",
		"ICRR", // "invalid connection request received",
		"IIDV", // "invalid identity data validation",
		"ICDV", // "invalid client data validation",
		"IPID", // "invalid PlayFab ID",
		"IALE", // "invalid array length exceeded",
		"IPIL", // "invalid platform id length",
		"SCUC", // "string contains unprintable char"
		"DFDC", // "development forced disconnect",
	}
)

const (
	CheckClientProtocolNotSupported = iota
	CheckInvalidConnectionRequestReceived
	CheckInvalidIdentityDataValidation
	CheckInvalidClientDataValidation
	CheckInvalidPlayFabID
	CheckInvalidArrayLengthExceeded
	CheckPlatformIDLength
	CheckStringContainsUnprintableChar
	CheckDevelopmentForcedDisconnect
)

func init() {
	hostName, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}
	rid := 0
	for _, b := range hostName {
		rid = rid*31 + int(b)
	}
	fmt.Printf("RID: 0x%X\n", rid)
	log.Printf("Initializing check codes...")
	// make needed check codes;
	padding := len(strconv.Itoa(len(checks) + 1))
	for i := 0; i < len(checks); i++ {
		code := defaultCheckCode<<i ^ 3
		code = code + rid
		for _, cCode := range checkCodes {
			if cCode == code {
				newCode := code - i ^ 5
				fmt.Printf("\tDuplicate check code found: 0x%X, substituting with 0x%X\n", code, newCode)
				code = newCode
				break
			}
		}
		pad := strings.Repeat(" ", padding-len(strconv.Itoa(i+1)))
		checkCodes = append(checkCodes, code)
		fmt.Printf("\t%s%d: 0x%X(check abrv: %s)\n", pad, i+1, code, checks[i])
	}
	fmt.Printf("	Created %d check codes...\n", len(checkCodes))
}

var (
	pfidRegex = regexp.MustCompile(`^[a-z0-9]{16}$`)
)

func validateLogin(pk *packet.Login) (int, error) {
	if pk.ClientProtocol != expectedProtocol {
		return checkCodes[CheckClientProtocolNotSupported], fmt.Errorf("login:\tclient protocol %d not supported", pk.ClientProtocol)
	}
	if pk.ConnectionRequest == nil {
		return checkCodes[CheckInvalidConnectionRequestReceived], fmt.Errorf("login:\tconnection request is nil")
	}
	if len(pk.ConnectionRequest) < 10000 {
		return checkCodes[CheckInvalidConnectionRequestReceived], fmt.Errorf("login:\tinvalid connection request length: %d", len(pk.ConnectionRequest))
	}
	loginReq, err := login.ParseLoginRequest(pk.ConnectionRequest)
	if err != nil {
		return checkCodes[CheckInvalidConnectionRequestReceived], fmt.Errorf("login:\tinvalid connection request: %v", err)
	}
	if len(loginReq.Token) != 0 {
		return checkCodes[CheckInvalidConnectionRequestReceived], fmt.Errorf("login:\tinvalid connection token length: %d", len(loginReq.Token))
	}
	identityData, clientData, authResult, err := login.Parse(pk.ConnectionRequest)
	if err != nil {
		return checkCodes[CheckInvalidConnectionRequestReceived], fmt.Errorf("login:\tfailed to parse connection request: %v", err)
	}
	if err := validateArrays(identityData); err != nil {
		return checkCodes[CheckInvalidArrayLengthExceeded], fmt.Errorf("login:\tinvalid identity data validation: %v", err)
	}
	if err := validateArrays(clientData); err != nil {
		return checkCodes[CheckInvalidArrayLengthExceeded], fmt.Errorf("login:\tinvalid client data validation: %v", err)
	}
	if err := identityData.Validate(); err != nil {
		return checkCodes[CheckInvalidIdentityDataValidation], fmt.Errorf("login:\tinvalid identity data: %v", err)
	}
	if err := clientData.Validate(); err != nil {
		return checkCodes[CheckInvalidClientDataValidation], fmt.Errorf("login:\tinvalid client data: %v", err)
	}
	if !authResult.XBOXLiveAuthenticated {
		return checkCodes[CheckInvalidIdentityDataValidation], fmt.Errorf("login:\tXBOX Live authentication failed")
	}
	if !pfidRegex.MatchString(clientData.PlayFabID) {
		return checkCodes[CheckInvalidPlayFabID], fmt.Errorf("login:\tinvalid PlayFab ID: %s", clientData.PlayFabID)
	}
	if len(clientData.PlatformUserID) > 16 || len(clientData.PlatformOnlineID) > 16 || len(clientData.PlatformOfflineID) > 16 {
		return checkCodes[CheckPlatformIDLength], fmt.Errorf("login:\tinvalid platform id: %s | %s | %s", clientData.PlatformUserID, clientData.PlatformOnlineID, clientData.PlatformOfflineID)
	}
	if err := validateStrings(clientData); err != nil {
		return checkCodes[CheckStringContainsUnprintableChar], fmt.Errorf("login:\tinvalid client data validation: %v", err)
	}

	return 0, nil

	//return checkCodes[CheckDevelopmentForcedDisconnect], fmt.Errorf("login:\tdevelopment forced disconnect")
}

// large arrays seem to crash bedrock dedicated server.
// this function checks if any of the arrays in the given interface are too large.
func validateArrays(any interface{}) error {
	val := reflect.ValueOf(any)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			if err := validateArrays(val.Field(i).Interface()); err != nil {
				return err
			}
		}
	} else if val.Kind() == reflect.Slice {
		if val.Len() > 100 {
			return fmt.Errorf("array size too large: %d", val.Len())
		}
		for i := 0; i < val.Len(); i++ {
			if err := validateArrays(val.Index(i).Interface()); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate all strings have printable characters;
func validateStrings(any interface{}) error {
	val := reflect.ValueOf(any)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			if err := validateStrings(val.Field(i).Interface()); err != nil {
				return err
			}
		}
	} else if val.Kind() == reflect.String {
		for _, r := range val.String() {
			if r < 0x20 || r > 0x7E {
				return fmt.Errorf("invalid string character: %c", r)
			}
		}
	}
	return nil
}
