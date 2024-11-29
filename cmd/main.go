package main

import (
	"authService/configs"
	"authService/internal/handlers"
	"authService/internal/models"
	"authService/internal/repositories"
	"authService/internal/services"
	"authService/pkg/db"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func main() {
	cfg := configs.LoadConfig()

	db := db.NewDb(cfg.Dsn)
	err := db.DB.AutoMigrate(&models.User{}, &models.RefreshToken{})
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	authRepo := repositories.NewAuthRepository(db)

	mockNotifier := &EmailNotifierMock{}
	authService := services.NewAuthService(authRepo, mockNotifier, cfg.JwtSecret)

	router := gin.Default()
	handlers.NewAuthHandler(router, authService)

	log.Printf("Server is running on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, router); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
