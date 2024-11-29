package models

type User struct {
	ID       string `gorm:"primaryKey"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}
