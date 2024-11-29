package handlers

import (
	"authService/internal/payload"
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
	r.GET("/auth/token/:id", handler.IssueTokens)
	r.POST("/auth/refresh/:id", handler.RefreshTokens)
}

func (h *AuthHandler) Register(c *gin.Context) {
	var request payload.RegisterRequest
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
	var request payload.RefreshTokensRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := ctx.Param("id")

	clientIP := ctx.ClientIP()
	tokens, err := h.service.RefreshTokens(userID, request.RefreshToken, clientIP)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tokens"})
		return
	}

	ctx.JSON(http.StatusOK, tokens)
}
