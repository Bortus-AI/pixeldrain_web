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
        
        // Set proper content type
        w.Header().Set("Content-Type", getMimeType(filePath))
        http.ServeFile(w, r, filePath)
    })

    // File upload endpoint
    router.PUT("/api/file/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", id)
        
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
    })

    // Thumbnail endpoint
    router.GET("/api/file/:id/thumbnail", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
        id := ps.ByName("id")
        filePath := filepath.Join("/mnt/minio", id)
        
        // For now, just serve the file as is
        // TODO: Implement actual thumbnail generation
        http.ServeFile(w, r, filePath)
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