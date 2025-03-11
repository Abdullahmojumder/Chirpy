package main

import (
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "os"
    "regexp"
    "sync/atomic"
    "time"
    "sort"

    "github.com/google/uuid"
    _ "github.com/lib/pq"
    "github.com/joho/godotenv"
    "github.com/Abdullahmojumder/chirpy/internal/auth"
    "github.com/Abdullahmojumder/chirpy/internal/database"
)

var profaneWords = []string{"kerfuffle", "sharbert", "fornax"}

type apiConfig struct {
    fileserverHits atomic.Int32
    dbQueries      *database.Queries
    platform       string
    jwtSecret      string
    polkaKey       string
}

type ChirpRequest struct {
    Body string `json:"body"`
}

type ChirpResponse struct {
    Error       string `json:"error,omitempty"`
    CleanedBody string `json:"cleaned_body,omitempty"`
}

type User struct {
    ID           uuid.UUID `json:"id"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
    Email        string    `json:"email"`
    IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
    ID        uuid.UUID `json:"id"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    Body      string    `json:"body"`
    UserID    uuid.UUID `json:"user_id"`
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
    respondWithJSON(w, code, map[string]string{"error": msg})
}

func cleanChirp(body string) string {
    for _, word := range profaneWords {
        re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
        body = re.ReplaceAllString(body, "****")
    }
    return body
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    var req struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
        respondWithError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    hashedPassword, err := auth.HashPassword(req.Password)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
        return
    }

    user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
        ID:            uuid.New(),
        Email:         req.Email,
        HashedPassword: hashedPassword,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to create user")
        return
    }

    responseUser := User{
        ID:          user.ID,
        CreatedAt:   user.CreatedAt,
        UpdatedAt:   user.UpdatedAt,
        Email:       user.Email,
        IsChirpyRed: user.IsChirpyRed,
    }

    respondWithJSON(w, http.StatusCreated, responseUser)
}

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    tokenString, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
        return
    }

    userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    var req struct {
        Body string `json:"body"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Body == "" {
        respondWithError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    cleanedBody := cleanChirp(req.Body)
    if len(cleanedBody) > 140 {
        respondWithError(w, http.StatusBadRequest, "Chirp is too long")
        return
    }

    chirpID := uuid.New()
    now := time.Now()

    chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
        ID:        chirpID,
        Body:      cleanedBody,
        UserID:    userID,
        CreatedAt: now,
        UpdatedAt: now,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to create chirp")
        return
    }

    responseChirp := Chirp{
        ID:        chirp.ID,
        CreatedAt: chirp.CreatedAt,
        UpdatedAt: chirp.UpdatedAt,
        Body:      chirp.Body,
        UserID:    chirp.UserID,
    }

    respondWithJSON(w, http.StatusCreated, responseChirp)
}


func (cfg *apiConfig) handlerGetAllChirps(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    // Get optional author_id query parameter
    authorIDStr := r.URL.Query().Get("author_id")
    var chirps []database.Chirp
    var err error

    if authorIDStr != "" {
        // Parse author_id as UUID
        authorID, err := uuid.Parse(authorIDStr)
        if err != nil {
            respondWithError(w, http.StatusBadRequest, "Invalid author_id format")
            return
        }
        // Fetch chirps by author
        chirps, err = cfg.dbQueries.GetChirpsByAuthor(r.Context(), authorID)
    } else {
        // Fetch all chirps
        chirps, err = cfg.dbQueries.GetAllChirps(r.Context())
    }

    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirps")
        return
    }

    // Get optional sort query parameter (default to "asc")
    sortOrder := r.URL.Query().Get("sort")
    if sortOrder == "" {
        sortOrder = "asc"
    }

    // Sort chirps in-memory by created_at
    if sortOrder == "desc" {
        sort.Slice(chirps, func(i, j int) bool {
            return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
        })
    } else { // "asc" or any invalid value defaults to ascending
        sort.Slice(chirps, func(i, j int) bool {
            return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
        })
    }

    // Convert to response format
    responseChirps := make([]Chirp, len(chirps))
    for i, chirp := range chirps {
        responseChirps[i] = Chirp{
            ID:        chirp.ID,
            CreatedAt: chirp.CreatedAt,
            UpdatedAt: chirp.UpdatedAt,
            Body:      chirp.Body,
            UserID:    chirp.UserID,
        }
    }

    respondWithJSON(w, http.StatusOK, responseChirps)
}

func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    chirpIDStr := r.PathValue("chirpID")
    if chirpIDStr == "" {
        respondWithError(w, http.StatusBadRequest, "Chirp ID is required")
        return
    }

    chirpID, err := uuid.Parse(chirpIDStr)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
        return
    }

    chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            respondWithError(w, http.StatusNotFound, "Chirp not found")
            return
        }
        respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirp")
        return
    }

    responseChirp := Chirp{
        ID:        chirp.ID,
        CreatedAt: chirp.CreatedAt,
        UpdatedAt: chirp.UpdatedAt,
        Body:      chirp.Body,
        UserID:    chirp.UserID,
    }

    respondWithJSON(w, http.StatusOK, responseChirp)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    type loginRequest struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    var req loginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
        respondWithError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    user, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
        return
    }

    if err := auth.CheckPasswordHash(req.Password, user.HashedPassword); err != nil {
        respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
        return
    }

    accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, 1*time.Hour)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to generate access token")
        return
    }

    refreshToken, err := auth.MakeRefreshToken()
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to generate refresh token")
        return
    }

    _, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
        Token:  refreshToken,
        UserID: user.ID,
    })
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to store refresh token")
        return
    }

    type loginResponse struct {
        ID           uuid.UUID `json:"id"`
        CreatedAt    time.Time `json:"created_at"`
        UpdatedAt    time.Time `json:"updated_at"`
        Email        string    `json:"email"`
        Token        string    `json:"token"`
        RefreshToken string    `json:"refresh_token"`
        IsChirpyRed  bool      `json:"is_chirpy_red"`
    }

    response := loginResponse{
        ID:           user.ID,
        CreatedAt:    user.CreatedAt,
        UpdatedAt:    user.UpdatedAt,
        Email:        user.Email,
        Token:        accessToken,
        RefreshToken: refreshToken,
        IsChirpyRed:  user.IsChirpyRed,
    }

    respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPut {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    tokenString, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
        return
    }

    userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    type updateRequest struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }

    var req updateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
        respondWithError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    hashedPassword, err := auth.HashPassword(req.Password)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to hash password")
        return
    }

    updatedUser, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
        ID:            userID,
        Email:         req.Email,
        HashedPassword: hashedPassword,
    })
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            respondWithError(w, http.StatusNotFound, "User not found")
            return
        }
        respondWithError(w, http.StatusInternalServerError, "Failed to update user")
        return
    }

    response := User{
        ID:          updatedUser.ID,
        CreatedAt:   updatedUser.CreatedAt,
        UpdatedAt:   updatedUser.UpdatedAt,
        Email:       updatedUser.Email,
        IsChirpyRed: updatedUser.IsChirpyRed,
    }

    respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodDelete {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    tokenString, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
        return
    }

    userID, err := auth.ValidateJWT(tokenString, cfg.jwtSecret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    chirpIDStr := r.PathValue("chirpID")
    if chirpIDStr == "" {
        respondWithError(w, http.StatusBadRequest, "Chirp ID is required")
        return
    }

    chirpID, err := uuid.Parse(chirpIDStr)
    if err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid chirp ID format")
        return
    }

    chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            respondWithError(w, http.StatusNotFound, "Chirp not found")
            return
        }
        respondWithError(w, http.StatusInternalServerError, "Failed to retrieve chirp")
        return
    }

    if chirp.UserID != userID {
        respondWithError(w, http.StatusForbidden, "You can only delete your own chirps")
        return
    }

    _, err = cfg.dbQueries.DeleteChirp(r.Context(), chirpID)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to delete chirp")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    if cfg.platform != "dev" {
        respondWithError(w, http.StatusForbidden, "Forbidden")
        return
    }

    err := cfg.dbQueries.DeleteAllUsers(r.Context())
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to delete users")
        return
    }

    w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    refreshToken, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
        return
    }

    user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
        return
    }

    accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, 1*time.Hour)
    if err != nil {
        respondWithError(w, http.StatusInternalServerError, "Failed to generate access token")
        return
    }

    type refreshResponse struct {
        Token string `json:"token"`
    }

    response := refreshResponse{
        Token: accessToken,
    }

    respondWithJSON(w, http.StatusOK, response)
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    refreshToken, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
        return
    }

    _, err = cfg.dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        respondWithError(w, http.StatusInternalServerError, "Failed to revoke token")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerPolkaWebhook(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        return
    }

    apiKey, err := auth.GetAPIKey(r.Header)
    if err != nil || apiKey != cfg.polkaKey {
        respondWithError(w, http.StatusUnauthorized, "Invalid or missing API key")
        return
    }

    type webhookRequest struct {
        Event string `json:"event"`
        Data  struct {
            UserID uuid.UUID `json:"user_id"`
        } `json:"data"`
    }

    var req webhookRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondWithError(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    if req.Event != "user.upgraded" {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    _, err = cfg.dbQueries.UpgradeUserToChirpyRed(r.Context(), req.Data.UserID)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            respondWithError(w, http.StatusNotFound, "User not found")
            return
        }
        respondWithError(w, http.StatusInternalServerError, "Failed to upgrade user")
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func main() {
    if err := godotenv.Load(); err != nil {
        fmt.Println("Warning: Could not load .env file")
    }

    dbURL := os.Getenv("DB_URL")
    if dbURL == "" {
        panic("DB_URL environment variable is not set")
    }

    jwtSecret := os.Getenv("TOKEN_SECRET")
    if jwtSecret == "" {
        panic("TOKEN_SECRET environment variable is not set")
    }

    polkaKey := os.Getenv("POLKA_KEY")
    if polkaKey == "" {
        panic("POLKA_KEY environment variable is not set")
    }

    platform := os.Getenv("PLATFORM")

    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        panic(fmt.Sprintf("Failed to connect to database: %v", err))
    }
    defer db.Close()

    dbQueries := database.New(db)

    apiCfg := &apiConfig{
        dbQueries: dbQueries,
        platform:  platform,
        jwtSecret: jwtSecret,
        polkaKey:  polkaKey,
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost {
            apiCfg.handlerCreateUser(w, r)
        } else if r.Method == http.MethodPut {
            apiCfg.handlerUpdateUser(w, r)
        } else {
            respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        }
    })
    mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodPost {
            apiCfg.handlerCreateChirp(w, r)
        } else if r.Method == http.MethodGet {
            apiCfg.handlerGetAllChirps(w, r)
        } else {
            respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        }
    })
    mux.HandleFunc("/api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet {
            apiCfg.handlerGetChirpByID(w, r)
        } else if r.Method == http.MethodDelete {
            apiCfg.handlerDeleteChirp(w, r)
        } else {
            respondWithError(w, http.StatusMethodNotAllowed, "Invalid method")
        }
    })
    mux.HandleFunc("/api/login", apiCfg.handlerLogin)
    mux.HandleFunc("/admin/reset", apiCfg.handlerReset)
    mux.HandleFunc("/api/refresh", apiCfg.handlerRefresh)
    mux.HandleFunc("/api/revoke", apiCfg.handlerRevoke)
    mux.HandleFunc("/api/polka/webhooks", apiCfg.handlerPolkaWebhook)

    server := &http.Server{
        Addr:    ":8080",
        Handler: mux,
    }

    fmt.Println("Server running on port 8080")
    if err := server.ListenAndServe(); err != nil {
        panic(err)
    }
}
