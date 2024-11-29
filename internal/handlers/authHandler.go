package handlers

import (
	"authService/internal/services"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthHandler struct {
	service *services.AuthService
}

func NewAuthHandler(r *gin.Engine, service *services.AuthService) {
	handler := &AuthHandler{service: service}

	r.POST("/auth/register", handler.Register)
	r.POST("/auth/token/:id", handler.IssueTokens)
	r.POST("/auth/refresh/:id", handler.RefreshTokens)
}

func (h *AuthHandler) Register(c *gin.Context) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userId, err := h.service.Register(request.Email, request.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user_id": userId})
}

func (h *AuthHandler) IssueTokens(ctx *gin.Context) {
	userID := ctx.Param("id")
	clientIP := ctx.ClientIP()

	user, err := h.service.GetUserByID(userID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "User  not found"})
		return
	}

	tokens, err := h.service.GenerateTokens(user.ID, clientIP)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) RefreshTokens(ctx *gin.Context) {
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := ctx.ShouldBindJSON(&requestBody); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := ctx.Param("id")

	isValid, err := h.service.ValidateRefreshToken(userID, requestBody.RefreshToken)
	if err != nil || !isValid {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	clientIP := ctx.ClientIP()
	tokens, err := h.service.GenerateTokens(userID, clientIP)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	if err = h.service.UpdateRefreshToken(userID, tokens.RefreshToken); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Token update failed"})
		return
	}
	ctx.JSON(http.StatusOK, tokens)
}