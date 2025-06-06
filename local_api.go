package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/julienschmidt/httprouter"
)

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

func main() {
    router := httprouter.New()
    
    // File info endpoint
    router.GET("/api/file/:id/info", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", id)
        
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
    })

    // File download endpoint
    router.GET("/api/file/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", id)
        
        http.ServeFile(w, r, filePath)
    })

    // Filesystem listing endpoint
    router.GET("/api/filesystem/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        path := ps.ByName("path")
        fullPath := filepath.Join("/mnt/minio", path)
        
        entries, err := os.ReadDir(fullPath)
        if err != nil {
            http.Error(w, "Directory not found", http.StatusNotFound)
            return
        }

        var response struct {
            Success           bool     `json:"success"`
            Name             string   `json:"name"`
            Path             string   `json:"path"`
            Type             string   `json:"type"`
            ChildDirectories []string `json:"child_directories"`
            ChildFiles       []string `json:"child_files"`
        }

        response.Success = true
        response.Name = filepath.Base(fullPath)
        response.Path = path
        response.Type = "directory"

        for _, entry := range entries {
            if entry.IsDir() {
                response.ChildDirectories = append(response.ChildDirectories, entry.Name())
            } else {
                response.ChildFiles = append(response.ChildFiles, entry.Name())
            }
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    })

    fmt.Println("Starting API server on :8776")
    http.ListenAndServe(":8776", router)
}

func getMimeType(path string) string {
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
    default:
        return "application/octet-stream"
    }
} 