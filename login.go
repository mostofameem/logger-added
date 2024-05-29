package handlers

import (
	"ecommerce/db"
	"ecommerce/logger"
	"ecommerce/models"
	"ecommerce/web/middlewares"
	"ecommerce/web/utils"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type LoginUser struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=20"`
}

func Login(w http.ResponseWriter, r *http.Request) {

	start := time.Now()
	logger.Info("Login request received",
		logger.Method(r.Method),
		logger.Path(r.URL.Path),
		logger.UserAgent(r.UserAgent()),
		logger.Ip(r.RemoteAddr),
	)

	var user LoginUser
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		logger.Error("Invalid request body",
			logger.Path(r.URL.Path),
			logger.Method(r.Method),
		)

		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = utils.Validate(user)
	if err != nil {
		logger.Error("Validation error",
			logger.Path(r.URL.Path),
			logger.Method(r.Method),
			logger.Extra(err.Error()),
		)

		utils.SendError(w, http.StatusBadRequest, err)
		return
	}

	err = db.Login(user.Email, user.Password)
	if err != nil {

		logger.Error("Login failed for user",
			logger.Path(r.URL.Path),
			logger.Method(r.Method),
			logger.Extra(user.Email),
			logger.Extra(err.Error()),
		)

		utils.SendError(w, http.StatusBadRequest, fmt.Errorf("wrong username / password "))
		return
	}

	var wg sync.WaitGroup
	var usr models.User

	wg.Add(1)
	go db.GetUser(user.Email, &usr, &wg)
	wg.Wait()

	accessToken, refreshToken, err := middlewares.GenerateToken(usr)

	if err != nil {

		logger.Error("Error generating token",
			logger.Path(r.URL.Path),
			logger.Method(r.Method),
			logger.Extra(err.Error()),
		)

		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	logger.Info("User logged in successfully",
		logger.Path(r.URL.Path),
		logger.Method(r.Method),
		logger.Extra(user.Email),
	)

	// logger.Info("Generated tokens",
	// 	logger.Path(r.URL.Path),
	// 	logger.Method(r.Method),
	// 	logger.Extra(fmt.Sprintf("AccessToken=%s, RefreshToken=%s", accessToken, refreshToken)),
	// )

	utils.SendBothData(w, accessToken, usr)
	log.Println(refreshToken)

	logger.Info("Login request processed",
		logger.Path(r.URL.Path),
		logger.Method(r.Method),
		logger.Latency(time.Since(start)),
	)
}
