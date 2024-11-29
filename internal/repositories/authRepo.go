package repositories

import (
	"authService/internal/models"
	"authService/pkg/db"
)

type AuthRepository struct {
	db *db.Db
}

func NewAuthRepository(db *db.Db) *AuthRepository {
	return &AuthRepository{db: db}
}

func (r *AuthRepository) Register(user models.User) error {
	return r.db.Create(&user).Error
}

func (r *AuthRepository) GetUserByID(userID string) (*models.User, error) {
	var user models.User
	if err := r.db.First(&user, "id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) StoreRefreshToken(userID, token, ip string) error {
	refreshToken := models.RefreshToken{UserID: userID, Token: token, Ip: ip}
	return r.db.Create(&refreshToken).Error
}

func (r *AuthRepository) UpdateRefreshToken(userID, token, ip string) error {
	return r.db.Exec("update refresh_tokens set token = ?, ip = ? where user_id = ?", token, ip, userID).Error
}

func (r *AuthRepository) GetHashedToken(userID string) (string, error) {
	var refreshToken models.RefreshToken
	if err := r.db.First(&refreshToken, "user_id = ?", userID).Error; err != nil {
		return "", err
	}
	return refreshToken.Token, nil
}
