package main

import (
    "encoding/json"
    "fmt"
    "io"
    "mime"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/julienschmidt/httprouter"
    "golang.org/x/crypto/bcrypt"
    "encoding/base64"
    "math/rand"
    "sync"
)

// User model and storage
var (
    usersFile = "users.json"
    usersMu   sync.Mutex
    sessions  = make(map[string]string) // token -> username
    sessionsMu sync.Mutex
)

type User struct {
    Username string `json:"username"`
    PasswordHash string `json:"password_hash"`
}

type Users struct {
    Users []User `json:"users"`
}

func loadUsers() (*Users, error) {
    usersMu.Lock()
    defer usersMu.Unlock()
    f, err := os.Open(usersFile)
    if err != nil {
        if os.IsNotExist(err) {
            return &Users{}, nil
        }
        return nil, err
    }
    defer f.Close()
    var u Users
    err = json.NewDecoder(f).Decode(&u)
    return &u, err
}

func saveUsers(u *Users) error {
    usersMu.Lock()
    defer usersMu.Unlock()
    f, err := os.Create(usersFile)
    if err != nil {
        return err
    }
    defer f.Close()
    return json.NewEncoder(f).Encode(u)
}

func findUser(username string) (*User, error) {
    u, err := loadUsers()
    if err != nil {
        return nil, err
    }
    for _, user := range u.Users {
        if user.Username == username {
            return &user, nil
        }
    }
    return nil, nil
}

func addUser(username, password string) error {
    u, err := loadUsers()
    if err != nil {
        return err
    }
    for _, user := range u.Users {
        if user.Username == username {
            return fmt.Errorf("user exists")
        }
    }
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    u.Users = append(u.Users, User{Username: username, PasswordHash: string(hash)})
    return saveUsers(u)
}

func randomToken() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}

func setSession(username string) string {
    token := randomToken()
    sessionsMu.Lock()
    sessions[token] = username
    sessionsMu.Unlock()
    return token
}

func getSession(r *http.Request) (string, bool) {
    // Check cookie
    if cookie, err := r.Cookie("session_token"); err == nil {
        sessionsMu.Lock()
        username, ok := sessions[cookie.Value]
        sessionsMu.Unlock()
        if ok {
            return username, true
        }
    }
    // Check bearer token
    auth := r.Header.Get("Authorization")
    if strings.HasPrefix(auth, "Bearer ") {
        token := strings.TrimPrefix(auth, "Bearer ")
        sessionsMu.Lock()
        username, ok := sessions[token]
        sessionsMu.Unlock()
        if ok {
            return username, true
        }
    }
    return "", false
}

type FileInfo struct {
    ID            string    `json:"id"`
    Name          string    `json:"name"`
    Size          int64     `json:"size"`
    MimeType      string    `json:"mime_type"`
    DateUpload    time.Time `json:"date_upload"`
    DateLastView  time.Time `json:"date_last_view"`
    Views         int       `json:"views"`
    ThumbnailHref string    `json:"thumbnail_href"`
}

type DirectoryEntry struct {
    Name      string    `json:"name"`
    Type      string    `json:"type"`
    Path      string    `json:"path"`
    Size      int64     `json:"size,omitempty"`
    MimeType  string    `json:"mime_type,omitempty"`
    DateModified time.Time `json:"date_modified,omitempty"`
}

func main() {
    router := httprouter.New()
    
    // File info endpoint
    router.GET("/api/file/:id/info", requireAuth(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params, username string) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", username, id)
        
        info, err := os.Stat(filePath)
        if err != nil {
            http.Error(w, "File not found", http.StatusNotFound)
            return
        }

        fileInfo := FileInfo{
            ID:            id,
            Name:          info.Name(),
            Size:          info.Size(),
            MimeType:      getMimeType(filePath),
            DateUpload:    info.ModTime(),
            DateLastView:  time.Now(),
            Views:         0,
            ThumbnailHref: fmt.Sprintf("/api/file/%s/thumbnail", id),
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(fileInfo)
    }))

    // File download endpoint
    router.GET("/api/file/:id", requireAuth(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params, username string) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", username, id)
        
        // Set proper content type
        w.Header().Set("Content-Type", getMimeType(filePath))
        http.ServeFile(w, r, filePath)
    }))

    // File upload endpoint
    router.PUT("/api/file/:id", requireAuth(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params, username string) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", username, id)
        
        // Create the file
        out, err := os.Create(filePath)
        if err != nil {
            http.Error(w, "Could not create file", http.StatusInternalServerError)
            return
        }
        defer out.Close()

        // Copy the uploaded file
        _, err = io.Copy(out, r.Body)
        if err != nil {
            http.Error(w, "Could not write file", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
    }))

    // Filesystem listing endpoint
    router.GET("/api/filesystem/*path", requireAuth(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params, username string) {
        path := ps.ByName("path")
        fullPath := filepath.Join("/mnt/minio", username, path)
        
        entries, err := os.ReadDir(fullPath)
        if err != nil {
            http.Error(w, "Directory not found", http.StatusNotFound)
            return
        }

        var response struct {
            Success           bool            `json:"success"`
            Name             string          `json:"name"`
            Path             string          `json:"path"`
            Type             string          `json:"type"`
            ChildDirectories []DirectoryEntry `json:"child_directories"`
            ChildFiles       []DirectoryEntry `json:"child_files"`
        }

        response.Success = true
        response.Name = filepath.Base(fullPath)
        response.Path = path
        response.Type = "directory"

        for _, entry := range entries {
            info, err := entry.Info()
            if err != nil {
                continue
            }

            de := DirectoryEntry{
                Name:          entry.Name(),
                Path:          filepath.Join(path, entry.Name()),
                DateModified:  info.ModTime(),
            }

            if entry.IsDir() {
                de.Type = "directory"
                response.ChildDirectories = append(response.ChildDirectories, de)
            } else {
                de.Type = "file"
                de.Size = info.Size()
                de.MimeType = getMimeType(filepath.Join(fullPath, entry.Name()))
                response.ChildFiles = append(response.ChildFiles, de)
            }
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }))

    // Thumbnail endpoint
    router.GET("/api/file/:id/thumbnail", requireAuth(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params, username string) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", username, id)
        
        // For now, just serve the file as is
        // TODO: Implement actual thumbnail generation
        http.ServeFile(w, r, filePath)
    }))

    // Registration endpoint
    router.POST("/api/user/register", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
        username := r.FormValue("username")
        password := r.FormValue("password")
        if username == "" || password == "" {
            http.Error(w, "username and password required", http.StatusBadRequest)
            return
        }
        if err := addUser(username, password); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"success":true}`))
    })

    // Login endpoint
    router.POST("/api/user/login", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
        username := r.FormValue("username")
        password := r.FormValue("password")
        user, err := findUser(username)
        if err != nil || user == nil {
            http.Error(w, "invalid credentials", http.StatusUnauthorized)
            return
        }
        if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
            http.Error(w, "invalid credentials", http.StatusUnauthorized)
            return
        }
        token := setSession(username)
        // Set cookie if requested
        if r.FormValue("cookie") == "1" {
            http.SetCookie(w, &http.Cookie{
                Name:     "session_token",
                Value:    token,
                Path:     "/",
                HttpOnly: true,
                Secure:   false, // set true if using HTTPS
                SameSite: http.SameSiteLaxMode,
            })
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(fmt.Sprintf(`{"success":true,"token":"%s"}`, token)))
    })

    // User info endpoint
    router.GET("/api/user/me", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
        username, ok := getSession(r)
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(fmt.Sprintf(`{"username":"%s"}`, username)))
    })

    fmt.Println("Starting API server on :8776")
    http.ListenAndServe(":8776", router)
}

func getMimeType(path string) string {
    // First try to get the MIME type from the file extension
    mimeType := mime.TypeByExtension(filepath.Ext(path))
    if mimeType != "" {
        return mimeType
    }

    // Fallback to our custom MIME type detection
    ext := strings.ToLower(filepath.Ext(path))
    switch ext {
    case ".jpg", ".jpeg":
        return "image/jpeg"
    case ".png":
        return "image/png"
    case ".gif":
        return "image/gif"
    case ".pdf":
        return "application/pdf"
    case ".txt":
        return "text/plain"
    case ".mp4":
        return "video/mp4"
    case ".mp3":
        return "audio/mpeg"
    case ".zip":
        return "application/zip"
    case ".tar":
        return "application/x-tar"
    case ".gz":
        return "application/gzip"
    default:
        return "application/octet-stream"
    }
}

// Auth middleware for file endpoints
requireAuth := func(h func(http.ResponseWriter, *http.Request, httprouter.Params, string)) httprouter.Handle {
    return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        username, ok := getSession(r)
        if !ok {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        h(w, r, ps, username)
    }
} 