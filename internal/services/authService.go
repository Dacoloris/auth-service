package services

import (
	"authService/internal/models"
	"authService/internal/repositories"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	mathrand "math/rand"
	"strconv"
	"time"
)

type EmailNotifier interface {
	SendWarningEmail(email string, oldIP string, newIP string) error
}

type AuthService struct {
	repo          *repositories.AuthRepository
	emailNotifier EmailNotifier
	jwtSecret     string
}

func NewAuthService(repo *repositories.AuthRepository, emailNotifier EmailNotifier, jwtSecret string) *AuthService {
	return &AuthService{
		repo:          repo,
		emailNotifier: emailNotifier,
		jwtSecret:     jwtSecret,
	}
}

func (s *AuthService) Register(email, password string) (string, error) {
	var user models.User
	user.ID = s.GenerateUserID()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user.Password = string(hash)
	user.Email = email

	return user.ID, s.repo.Register(user)
}

func (s *AuthService) GenerateTokens(userID, clientIP string) (models.Tokens, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"user_id": userID,
		"ip":      clientIP,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return models.Tokens{}, err
	}

	refreshToken := make([]byte, 32)
	if _, err := rand.Read(refreshToken); err != nil {
		return models.Tokens{}, err
	}
	refreshTokenBase64 := base64.StdEncoding.EncodeToString(refreshToken)

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshTokenBase64), bcrypt.DefaultCost)
	if err != nil {
		return models.Tokens{}, err
	}

	err = s.repo.StoreRefreshToken(userID, string(hashedToken), clientIP)
	if err != nil {
		return models.Tokens{}, err
	}

	return models.Tokens{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenBase64,
	}, nil
}

func (s *AuthService) ValidateRefreshToken(userID string, refreshToken string) (bool, error) {
	hashedToken, err := s.repo.GetHashedToken(userID)
	if err != nil {
		return false, err
	}

	return bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken)) == nil, nil
}

func (s *AuthService) RefreshTokens(userID string, refreshToken string, clientIP string) (models.Tokens, error) {
	ok, err := s.ValidateRefreshToken(userID, refreshToken)
	if err != nil {
		return models.Tokens{}, err
	} else if !ok {
		return models.Tokens{}, fmt.Errorf("not valid token")
	}

	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return models.Tokens{}, err
	}
	if user.IP != clientIP {
		if err = s.emailNotifier.SendWarningEmail(user.Email, user.IP, clientIP); err != nil {
			return models.Tokens{}, err
		}
	}

	tokens, err := s.GenerateTokens(userID, clientIP)
	if err != nil {
		return models.Tokens{}, err
	}

	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(tokens.RefreshToken), bcrypt.DefaultCost)
	if err = s.repo.UpdateRefreshToken(userID, string(hashedToken), clientIP); err != nil {
		return models.Tokens{}, err
	}

	return tokens, nil
}

func (s *AuthService) GetUserByID(userID string) (*models.User, error) {
	return s.repo.GetUserByID(userID)
}

func (s *AuthService) GenerateUserID() string {
	userID := mathrand.Intn(90000) + 10000
	return strconv.Itoa(userID)
}

func (s *AuthService) UpdateRefreshToken(userId, token, ip string) error {
	return s.repo.UpdateRefreshToken(userId, token, ip)
}
