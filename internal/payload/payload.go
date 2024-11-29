package payload

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshTokensRequest struct {
	RefreshToken string `json:"refresh_token"`
}
