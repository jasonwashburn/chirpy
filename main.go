package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jasonwashburn/chirpy/internal/auth"
	"github.com/jasonwashburn/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const port string = ":8080"

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	tokenSecret    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

var cfg apiConfig = apiConfig{
	fileserverHits: atomic.Int32{},
}

type errorResponse struct {
	Error string `json:"error"`
}

func sendServerError(w http.ResponseWriter, message string) {
	log.Printf("Error: %s", message)
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(errorResponse{Error: message})
}

func main() {
	godotenv.Load()
	tokenSecret := os.Getenv("TOKEN_SECRET")
	cfg.tokenSecret = tokenSecret
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	dbQueries := database.New(db)
	cfg.dbQueries = dbQueries

	mux := http.NewServeMux()
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerHealthz)
	mux.HandleFunc("GET /admin/metrics", handlerMetrics)
	mux.HandleFunc("POST /admin/reset", handlerReset)
	mux.HandleFunc("POST /api/chirps", handlerCreateChirp)
	mux.HandleFunc("POST /api/users", handlerCreateUser)
	mux.HandleFunc("PUT /api/users", handlerUpdateUser)
	mux.HandleFunc("GET /api/chirps", handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirp_id}", handlerGetChirpByID)
	mux.HandleFunc("DELETE /api/chirps/{chirp_id}", handlerDeleteChirp)
	mux.HandleFunc("POST /api/login", handlerLogin)
	mux.HandleFunc("POST /api/refresh", handlerRefresh)
	mux.HandleFunc("POST /api/revoke", handlerRevokeRefreshToken)
	mux.HandleFunc("POST /api/polka/webhooks", handlerPolkaWebhook)
	srv := http.Server{
		Handler: mux,
		Addr:    port,
	}

	fmt.Printf("Starting server on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}

func handlerHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handlerMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func handlerReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	if os.Getenv("PLATFORM") != "dev" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{Error: "Forbidden"})
		return
	}
	err := cfg.dbQueries.ResetUsers(r.Context())
	if err != nil {
		log.Printf("Error resetting users: %v\n", err)
		sendServerError(w, "Something went wrong")
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0\n"))
	log.Println("Users reset")
}

type chirpResponseFormat struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    string    `json:"user_id"`
}

func chirpResponseFromDBChirp(chirp database.Chirp) chirpResponseFormat {
	return chirpResponseFormat{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
	}
}

type UserResponseFormat struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

func userResponseFromDBUser(user database.User) UserResponseFormat {
	return UserResponseFormat{
		ID:          user.ID.String(),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
}

func handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	if userID == uuid.Nil {
		log.Printf("Invalid user ID: %v", userID)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	// Validate user hasn't been removed since JWT was issued
	_, err = cfg.dbQueries.GetUserByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}

	if err = decoder.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
		return
	}

	if len(params.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Chirp is too long"})
		return
	}

	cleanedBody := replaceBadWords(params.Body)
	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{Error: "Something went wrong"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(chirpResponseFromDBChirp(chirp))
}

func handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chirp_id")
	chirpID, err := uuid.Parse(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Invalid chirp ID"})
		return
	}
	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		log.Printf("Error getting chirp by ID: %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errorResponse{Error: "Chirp not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(chirpResponseFromDBChirp(chirp))
}

func handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		sendServerError(w, "Something went wrong")
		return
	}
	responseChirps := []chirpResponseFormat{}
	for _, chirp := range chirps {
		responseChirps = append(responseChirps, chirpResponseFromDBChirp(chirp))
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseChirps)
}

func handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		sendServerError(w, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		sendServerError(w, "Something went wrong")
		return
	}
	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(userResponseFromDBUser(user))
}

func handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	if params.Email == "" || params.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Email and password are required"})
		return
	}

	if userID == uuid.Nil {
		log.Printf("Invalid user ID: %v", userID)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}
	user, err := cfg.dbQueries.GetUserByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}
	newHashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	user, err = cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          params.Email,
		HashedPassword: newHashedPassword,
	})
	if err != nil {
		log.Printf("Error updating user: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userResponseFromDBUser(user))
}

func handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		log.Printf("Error getting user by email: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	if !auth.CheckPasswordHash(params.Password, user.HashedPassword) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Invalid email or password"})
		return
	}

	expiresIn := 3600 * time.Second
	token, err := auth.MakeJWT(user.ID, cfg.tokenSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error making refresh token: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}
	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		UserResponseFormat
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		UserResponseFormat: userResponseFromDBUser(user),
		Token:              token,
		RefreshToken:       refreshToken,
	})
}

func handlerRefresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromHeader, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}
	refreshToken, err := cfg.dbQueries.GetRefreshTokenByToken(r.Context(), refreshTokenFromHeader)
	if err != nil {
		log.Printf("Error getting refresh token by token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	if refreshToken.RevokedAt.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	expiresIn := 3600 * time.Second
	token, err := auth.MakeJWT(refreshToken.UserID, cfg.tokenSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(struct {
		Token string `json:"token"`
	}{
		Token: token,
	})
}

func handlerRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		log.Printf("Error revoking refresh token: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
	json.NewEncoder(w).Encode(errorResponse{Error: "Refresh token revoked"})
}

func handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		log.Printf("Error validating JWT: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	if userID == uuid.Nil {
		log.Printf("Invalid user ID: %v", userID)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{Error: "Unauthorized"})
		return
	}

	chirpID := r.PathValue("chirp_id")
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{Error: "Invalid chirp ID"})
		return
	}

	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpUUID)
	if err != nil {
		log.Printf("Error getting chirp by ID: %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errorResponse{Error: "Chirp not found"})
		return
	}

	if chirp.UserID != userID {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{Error: "Forbidden"})
		return
	}

	err = cfg.dbQueries.DeleteChirp(r.Context(), chirpUUID)
	if err != nil {
		log.Printf("Error deleting chirp: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
	json.NewEncoder(w).Encode(errorResponse{Error: "Chirp deleted"})
}

func handlerPolkaWebhook(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	if params.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userUUID, err := uuid.Parse(params.Data.UserID)
	if err != nil {
		log.Printf("Error parsing user ID: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	_, err = cfg.dbQueries.GetUserByID(r.Context(), userUUID)
	if err != nil {
		log.Printf("Error getting user by ID: %v", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errorResponse{Error: "User not found"})
		return
	}

	_, err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), userUUID)
	if err != nil {
		log.Printf("Error upgrading user to Chirpy Red: %v", err)
		sendServerError(w, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func replaceBadWords(body string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	splitBody := strings.Split(body, " ")
	for i, word := range splitBody {
		for _, badWord := range badWords {
			if strings.ToLower(word) == badWord {
				splitBody[i] = "****"
			}
		}
	}
	return strings.Join(splitBody, " ")
}
