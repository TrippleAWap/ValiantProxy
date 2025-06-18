package login

func ParseLoginRequest(requestData []byte) (*request, error) {
	return parseLoginRequest(requestData)
}