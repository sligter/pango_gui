package server

import (
	"bufio"
	"context"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

var (
	uploadDir      string
	sharedFiles    = make(map[string]string)
	users          map[string]string                           // 用户名:密码映射，生产环境中应使用加密密码
	sessions                         = make(map[string]string) // 会话ID和用户名的映射
	downloadCounts                   = make(map[string]int)    //统计下载次数
	maxUploadSize  int64             = 100 << 30
)

// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool {
// 		return true
// 	},
// }

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

var srv *http.Server

func StartServer(uploadDirPath, username, password, port, domain string) error {
	//解析命令行参数
	flag.Parse()

	// 如果没有提供-upload-dir参数，使用当前工作目录
	if uploadDirPath == "" {
		var err error
		uploadDir, err = os.Getwd() // 获取当前工作目录
		if err != nil {
			log.Fatalf("Error getting current directory: %v", err)
		}
	} else {
		uploadDir = uploadDirPath // 将命令行参数赋给全局变量uploadDir
	}
	// 使用命令行参数或默认值设置用户名和密码
	users = map[string]string{username: password}

	// 在程序启动时创建自定义上传目录
	err := os.MkdirAll(uploadDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating upload directory: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("", http.FileServer(http.FS(staticFiles))))
	mux.HandleFunc("/", ensureLoggedIn(indexHandler))
	mux.HandleFunc("/upload", ensureLoggedIn(uploadHandler))
	mux.HandleFunc("/files", ensureLoggedIn(filesHandler))
	mux.HandleFunc("/shared/", sharedDownloadHandler)      // 新增共享文件下载处理函数
	mux.HandleFunc("/shared-folder/", sharedFolderHandler) // 文件夹分享
	mux.HandleFunc("/download", ensureLoggedIn(downloadHandler))
	mux.HandleFunc("/download-share", downloadshareHandler)
	mux.HandleFunc("/share", ensureLoggedIn(shareHandler))
	mux.HandleFunc("/login", loginFormHandler)
	mux.HandleFunc("/login-submit", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/new-folder", ensureLoggedIn(newFolderHandler))
	mux.HandleFunc("/rename", ensureLoggedIn(renameHandler))
	mux.HandleFunc("/move", ensureLoggedIn(moveHandler))
	mux.HandleFunc("/new-text-file", ensureLoggedIn(newTextFileHandler))
	mux.Handle("/statics/", static_ensureLoggedIn(http.StripPrefix("/statics/", http.FileServer(http.Dir(uploadDir)))))
	mux.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		// 从POST请求中获取文件路径和内容
		filePath := r.FormValue("file")
		content := r.FormValue("content")
		// 解码文件路径
		decodedFilePath, err := url.QueryUnescape(filePath)
		if err != nil {
			http.Error(w, "Unable to decode file path", http.StatusBadRequest)
			return
		}
		// 将内容写入文件
		fullPath := filepath.Join(uploadDir, decodedFilePath)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		if err != nil {
			http.Error(w, "Unable to save the file", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/delete", deleteHandler)

	if port == "" {
		port = "2333"
	}
	localIP := getLocalIP()
	// 判断是否提供了绑定域名
	listenAddress := "0.0.0.0:" + port // 默认监听地址
	priAddress := localIP + ":" + port
	if domain != "" {
		listenAddress = domain // 使用提供的域名和端口
	}
	srv = &http.Server{
		Addr:         listenAddress,        // or domain:port based on earlier logic
		Handler:      mux,                  // Use the ServeMux we created
		ReadTimeout:  365 * 24 * time.Hour, // 设置为一年
		WriteTimeout: 365 * 24 * time.Hour,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting server: %v", err)
		}
	}()
	fmt.Printf("Server folder on %s\n", uploadDir)
	fmt.Printf("Server started on %s\n", listenAddress)
	fmt.Printf("Server started on ipnet %s\n", priAddress)
	return nil
}

func StopServer() {
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down server: %v", err)
		} else {
			log.Println("Server has been gracefully stopped")
		}
		srv = nil // Set srv to nil to indicate it's stopped
	}
}

func ensureLoggedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func static_ensureLoggedIn(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoggedIn(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func isLoggedIn(r *http.Request) bool {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	username, exists := sessions[sessionCookie.Value]
	return exists && username != ""
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// 主页面的内容，例如上传表单
	w.Header().Set("Server", "pango")
	filesHandler(w, r)
	//http.Redirect(w, r, "/files?path="+url.QueryEscape(uploadDir), http.StatusFound)
}

func loginFormHandler(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// 获取本地图片文件的URL
	imageURL := "/static/images/backup-background.jpgs"
	tmpl := template.Must(template.New("login-form").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Login - Pango</title>
		<link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
		<link href="/static/css/bootstrap.min.css" rel="stylesheet">
		<style>
			body {
				height: 100vh;
				background-image: url('{{ .BackgroundImageURL }}?{{ .RandomValue }}');
				background-size: cover;
				background-position: center;
				background-repeat: no-repeat;
				display: flex;
				align-items: center;
				justify-content: center;
			}
			.login-container {
				background-color: rgba(255, 255, 255, 0.8);
				padding: 30px;
				border-radius: 10px;
				box-shadow: 0 0 10px rgba(0,0,0,0.1);
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 login-container">
					<h2 class="text-center mb-4">Pango</h2>
					<form action="/login-submit" method="post">
						<div class="form-group">
							<input type="text" class="form-control" name="username" placeholder="Username" required>
						</div>
						<div class="form-group">
							<input type="password" class="form-control" name="password" placeholder="Password" required>
						</div>
						<button type="submit" class="btn btn-primary btn-block">Login</button>
					</form>
				</div>
			</div>
		</div>
		<script src="/static/jquery/jquery-3.5.1.slim.min.js"></script>
		<script src="/static/js/popper.min.js"></script>
		<script src="/static/js/bootstrap.min.js"></script>
	</body>
	</html>
    `))

	randomValue := rand.Int63()
	data := struct {
		BackgroundImageURL string
		RandomValue        int64
	}{
		BackgroundImageURL: imageURL,
		RandomValue:        randomValue,
	}

	tmpl.Execute(w, data)

}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if checkCredentials(username, password) {
		sessionToken := createSessionToken()
		sessions[sessionToken] = username // 将会话ID与用户名关联
		// 设置 cookie 的有效期为一月
		expiration := time.Now().Add(30 * 24 * time.Hour)
		// 设置cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiration,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 删除会话
	delete(sessions, sessionCookie.Value)

	// 删除cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

// checkCredentials 检查提供的用户名和密码是否匹配
func checkCredentials(username, password string) bool {
	pass, exists := users[username]
	return exists && pass == password
}

func createSessionToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newFolderHandler(w http.ResponseWriter, r *http.Request) {
	currentPath := r.URL.Query().Get("path") // 获取当前路径

	if r.Method == http.MethodPost {
		folderName := r.FormValue("folder_name")
		if folderName == "" {
			http.Error(w, "Folder name cannot be empty", http.StatusBadRequest)
			return
		}

		// 创建新的文件夹
		fullPath := filepath.Join(uploadDir, currentPath, folderName)
		err := os.Mkdir(fullPath, os.ModePerm)
		if err != nil {
			http.Error(w, "Failed to create folder: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 重定向回当前路径
		http.Redirect(w, r, "/files?path="+url.QueryEscape(filepath.Join(currentPath, folderName)), http.StatusFound)
	} else {
		// 显示创建新文件夹的表单
		tmpl := template.Must(template.New("new-folder-form").Parse(`
            <h1>Create New Folder</h1>
            <form action="/new-folder?path={{.}}" method="post">
                <input type="text" name="folder_name" placeholder="Folder Name">
                <input type="submit" value="Create">
            </form>
        `))
		tmpl.Execute(w, currentPath) // 传递当前路径作为参数
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	currentPath := r.URL.Query().Get("path")
	fullPath := filepath.Join(uploadDir, currentPath)

	err := os.MkdirAll(fullPath, os.ModePerm)
	if err != nil {
		http.Error(w, "Unable to create directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置最大请求体大小
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Error parsing multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 使用 sync.Pool 来重用缓冲区
	bufferPool := sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB 缓冲区
		},
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Error reading multipart form: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer part.Close()

		fileName := part.FileName()
		if fileName == "" {
			continue
		}

		var filePath string
		if part.FormName() == "files" {
			filePath = filepath.Join(fullPath, filepath.Base(fileName))
		} else if part.FormName() == "folder" {
			relativePath := filepath.ToSlash(fileName)
			filePath = filepath.Join(fullPath, relativePath)
			if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
				http.Error(w, "Unable to create directory for file: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			continue
		}

		dst, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			http.Error(w, "Unable to create the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		// 使用缓冲的写入器
		bufWriter := bufio.NewWriterSize(dst, 1024*1024) // 1MB 缓冲区

		// 从池中获取缓冲区
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)

		written, err := io.CopyBuffer(bufWriter, io.LimitReader(part, maxUploadSize+1), buffer)
		if err != nil {
			http.Error(w, "Error writing file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 刷新缓冲的写入器
		if err := bufWriter.Flush(); err != nil {
			http.Error(w, "Error flushing file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if written > maxUploadSize {
			os.Remove(filePath)
			http.Error(w, "File too large: "+fileName, http.StatusBadRequest)
			return
		}
	}

	http.Redirect(w, r, "/files?path="+url.QueryEscape(currentPath), http.StatusFound)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "No file name specified", http.StatusBadRequest)
		return
	}
	fullPath := filepath.Join(uploadDir, fileName)

	// Open the file for reading
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Get the file size
	info, err := file.Stat()
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Set the Content-Type header to the appropriate value
	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Set the Content-Disposition header to specify the file name
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(fileName))

	// Increase the download count for the file
	downloadCounts[fileName]++

	// Send the file
	http.ServeContent(w, r, fileName, info.ModTime(), file)
}

func downloadshareHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "No file name specified", http.StatusBadRequest)
		return
	}
	fullPath := filepath.Join(uploadDir, fileName)

	// Open the file for reading
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Get the file size
	info, err := file.Stat()
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Set the Content-Type header to the appropriate value
	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Set the Content-Disposition header to specify the file name
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(fileName))

	// Increase the download count for the file
	downloadCounts[fileName]++

	// Send the file
	http.ServeContent(w, r, fileName, info.ModTime(), file)
}

func sharedDownloadHandler(w http.ResponseWriter, r *http.Request) {
	shareID := r.URL.Path[len("/shared/"):]
	if shareID == "" {
		http.Error(w, "Invalid share ID", http.StatusBadRequest)
		return
	}

	fileName, ok := sharedFiles[shareID]
	if !ok {
		http.Error(w, "Invalid share ID", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, fileName)
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File or directory not found", http.StatusNotFound)
		return
	}

	if info.IsDir() {
		// 如果是文件夹，重定向到共享文件夹处理函数
		http.Redirect(w, r, "/shared-folder/"+shareID, http.StatusFound)
	} else {
		// 如果是文件，提供文件下载
		serveFile(w, fileName)
	}
}

func serveFile(w http.ResponseWriter, fileName string) {
	filePath := filepath.Join(uploadDir, fileName)
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "File not found: "+err.Error(), http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
	w.Header().Set("Content-Type", "application/octet-stream")

	io.Copy(w, file)
}

// 替换原有的 shareHandler 函数
func shareHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "No file name specified", http.StatusBadRequest)
		return
	}

	// 解码 URL 编码的文件名
	decodedFileName, err := url.QueryUnescape(fileName)
	if err != nil {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}

	// 统一路径分隔符
	decodedFileName = filepath.FromSlash(decodedFileName)

	// 构建完整的文件路径
	filePath := filepath.Join(uploadDir, decodedFileName)

	// 检查文件或目录是否存在
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File or directory not found", http.StatusNotFound)
		return
	}

	// 生成分享 ID
	shareID := generateShareID()

	// 保存相对路径而不是完整路径
	sharedFiles[shareID] = decodedFileName

	var shareURL string
	if info.IsDir() {
		shareURL = fmt.Sprintf("http://%s/shared-folder/%s", r.Host, shareID)
	} else {
		shareURL = fmt.Sprintf("http://%s/shared/%s", r.Host, shareID)
	}

	// 返回 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": shareURL})
}

func isMediaFile(fileName string) bool {
	// 仅检查几种常见的媒体文件扩展名
	mediaExtensions := []string{".mp4", ".mp3", ".avi", ".wav", ".mov", ".ts", ".m4a", ".amr", ".flac", ".aac", ".mkv"}
	for _, ext := range mediaExtensions {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			return true
		}
	}
	return false
}

func isJPEGFile(fileName string) bool {
	// 仅检查几种常见的图片文件扩展名
	jpgExtensions := []string{".jpg", ".png", ".jpeg", ".tif", ".gif", ".ico", ".bmp"}
	for _, ext := range jpgExtensions {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			return true
		}
	}
	return false
}

func isTextFile(fileName string) bool {
	// 仅检查几种常见的文本文件扩展名
	textExtensions := []string{".txt", ".md", ".csv", ".json", ".xml", ".html", ".js", ".css", ".py", ".java", ".c", ".cpp", ".sh", ".json", ".go", ".r", ".rs"}
	for _, ext := range textExtensions {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			return true
		}
	}
	return false
}

func generateMediaPlayer(filePath string, id string) string {
	// 确定是音频还是视频文件
	if strings.HasSuffix(strings.ToLower(filePath), ".mp3") || strings.HasSuffix(strings.ToLower(filePath), ".wav") {
		return fmt.Sprintf(`<button onclick="createAudioPlayer('%s', '%s')">Play</button><div id="%s"></div>`, url.QueryEscape(filePath), id, id)
	} else {
		return fmt.Sprintf(`<button onclick="createVideoPlayer('%s', '%s')">Play</button><div id="%s"></div>`, url.QueryEscape(filePath), id, id)
	}
}

func generateImagePreview(filePath string, id string) string {
	return fmt.Sprintf(`<button onclick="createImagePreview('%s', '%s')">Preview</button><div id="%s"></div>`, url.QueryEscape(filePath), id, id)
}

func generateTextPreview(filePath string, id string) string {
	return fmt.Sprintf(`<button onclick="createTextPreview('%s', '%s')">Preview/Edit</button><div id="%s"></div>`, url.QueryEscape(filePath), id, id)
}

// sharedFilesHandler用于显示通过分享链接访问的文件夹和文件列表
func sharedFilesHandler(w http.ResponseWriter, r *http.Request, sharedPath string) {
	fullPath := filepath.Join(uploadDir, sharedPath)

	files, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Unable to read the directory", http.StatusInternalServerError)
		return
	}

	// Sort files: directories first, then by name
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir() && !files[j].IsDir() {
			return true
		}
		if !files[i].IsDir() && files[j].IsDir() {
			return false
		}
		return files[i].Name() < files[j].Name()
	})

	fmt.Fprintf(w, `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Pango Shared Files</title>
		<link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
        <link rel="stylesheet" href="/static/css/bootstrap.min.css">
        <link rel="stylesheet" href="/static/css/codemirror.min.css">
        <style>
            .file-item {
                padding: 15px;
                border-bottom: 1px solid #eee;
                transition: background-color 0.3s;
            }
            .file-item:hover {
                background-color: #f8f9fa;
            }
            .btn {
                border-radius: 20px;
                padding: 5px 15px;
                margin: 2px;
                transition: all 0.3s;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            }
            .preview-container {
                margin-top: 15px;
                margin-bottom: 15px;
            }
            .CodeMirror {
                height: 300px;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            @media (max-width: 768px) {
                .btn-group-sm > .btn {
                    padding: 3px 8px;
                    font-size: 0.75rem;
                }
                .file-item .row {
                    flex-direction: column;
                }
                .file-item .col-md-6 {
                    width: 100%%;
                    margin-bottom: 10px;
                }
                .btn-group {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="container mt-4">
            <h1 class="mb-4">Shared Files in %s</h1>
            <div class="file-list">
    `, sharedPath)

	for i, file := range files {
		fileName := file.Name()
		filePath := filepath.Join(sharedPath, fileName)
		relativeFilePath := filePath

		info, err := file.Info()
		if err != nil {
			http.Error(w, "Unable to get file info", http.StatusInternalServerError)
			return
		}
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		var fileSize string
		if file.IsDir() {
			fileSize = "N/A"
			shareID := findShareID(filePath)
			fmt.Fprintf(w, `
                <div class="file-item">
                    <div class="row align-items-center">
                        <div class="col-md-6 mb-2 mb-md-0">
                            <strong>[Folder] %s</strong><br>
                            <small class="text-muted">Last modified: %s</small>
                        </div>
                        <div class="col-md-6">
                            <div class="btn-group btn-group-sm d-flex flex-wrap justify-content-end" role="group">
                                <a href='/shared-folder/%s' class="btn btn-primary">Open</a>
                            </div>
                        </div>
                    </div>
                </div>
            `, fileName, modTime, shareID)
		} else {
			fileSize = fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			fmt.Fprintf(w, `
                <div class="file-item">
                    <div class="row align-items-center">
                        <div class="col-md-6 mb-2 mb-md-0">
                            <strong>%s</strong><br>
                            <small class="text-muted">Size: %s, Last modified: %s</small>
                        </div>
                        <div class="col-md-6">
                            <div class="btn-group btn-group-sm d-flex flex-wrap justify-content-end" role="group">
                                <a href='/download-share?file=%s' class="btn btn-primary">Download</a>
            `, fileName, fileSize, modTime, url.QueryEscape(relativeFilePath))

			if isMediaFile(fileName) || isJPEGFile(fileName) || isTextFile(fileName) {
				fmt.Fprintf(w, `
                                <button onclick="%s('%s', '%s')" class="btn btn-outline-secondary">Preview</button>
                `, getPreviewFunction(fileName), url.QueryEscape(relativeFilePath), "preview"+strconv.Itoa(i))
			}

			fmt.Fprintf(w, `
                            </div>
                        </div>
                    </div>
                    <div class="preview-container" id="%s"></div>
                </div>
            `, "preview"+strconv.Itoa(i))
		}
	}

	fmt.Fprintf(w, `
            </div>
        </div>
        <script src="/static/jquery/jquery-3.5.1.slim.min.js"></script>
        <script src="/static/js/popper.min.js"></script>
        <script src="/static/js/bootstrap.min.js"></script>
        <script src="/static/js/codemirror.min.js"></script>
        <script src="/static/js/javascript.min.js"></script>
        <script src="/static/js/xml.min.js"></script>
        <script src="/static/js/htmlmixed.min.js"></script>
        <script src="/static/js/css.min.js"></script>
        <script src="/static/js/markdown.min.js"></script>

		<link rel="stylesheet" href="/static/css/codemirror.min.css">
		<link rel="stylesheet" href="/static/css/monokai.min.css">
		<link rel="stylesheet" href="/static/css/dracula.min.css">
		<script src="/static/js/python.min.js"></script>
		<script src="/static/js/go.min.js"></script>
        <script>
        function createMediaPlayer(filePath, id) {
            var playerElement = document.getElementById(id);
            if (playerElement.innerHTML !== '') {
                playerElement.innerHTML = '';
            } else {
                var fileExtension = filePath.split('.').pop().toLowerCase();
                if (fileExtension === 'mp3' || fileExtension === 'wav') {
                    playerElement.innerHTML = '<audio controls preload="auto" style="width: 60%%;"><source src="/download-share?file=' + filePath + '" type="audio/' + fileExtension + '">Your browser does not support the audio element.</audio>';
                } else {
                    playerElement.innerHTML = '<video controls preload="auto" style="width: 60%%;"><source src="/download-share?file=' + filePath + '" type="video/' + fileExtension + '">Your browser does not support the video element.</video>';
                }
            }
        }

        function createImagePreview(filePath, id) {
            var previewElement = document.getElementById(id);
            if (previewElement.innerHTML !== '') {
                previewElement.innerHTML = '';
            } else {
                previewElement.innerHTML = '<img src="/download-share?file=' + filePath + '" alt="Image preview" style="max-width: 60%%;">';
            }
        }

        function createTextPreview(filePath, id) {
            var previewElement = document.getElementById(id);
            if (previewElement.innerHTML !== '') {
                previewElement.innerHTML = '';
            } else {
                fetch('/download-share?file=' + filePath)
				.then(response => response.text())
				.then(data => {
					previewElement.innerHTML = '<textarea id="textarea' + id + '"></textarea>';
					
					var editor = CodeMirror.fromTextArea(document.getElementById('textarea' + id), {
						lineNumbers: true,
						mode: getCodeMirrorMode(filePath),
						theme: 'dracula',
						readOnly: true,
						autoCloseBrackets: true,
						autofocus: true,
						matchBrackets: true,
						indentUnit: 4,
						indentWithTabs: true
					});
					
					editor.setValue(data);
					window['editor' + id] = editor;
				});
            }
        }

        function getCodeMirrorMode(filePath) {
		var extension = filePath.split('.').pop().toLowerCase();
		switch (extension) {
			case 'js':
				return 'javascript';
			case 'html':
				return 'htmlmixed';
			case 'css':
				return 'css';
			case 'py':
				return 'python';
			case 'go':
				return 'text/x-go';
			case 'xml':
				return 'xml';
			case 'json':
				return { name: 'javascript', json: true };
			// 添加更多文件类型
			default:
				return 'text/plain';
		}
	}
        </script>

		<script>
		function goBack() {
			window.history.back();
		}
		</script>

    </body>
    </html>
    `)

	// 添加返回上一级文件夹的链接

	if sharedPath != "" {
		fmt.Fprintf(w, `
			<div class="mt-4">
				<button onclick="goBack()" class="btn btn-secondary">Back</button>
			</div>
		`)
	}
}

// findShareID 通过文件路径查找共享ID
func findShareID(filePath string) string {
	for id, path := range sharedFiles {
		if path == filePath {
			return id
		}
	}
	// 如果没有找到，生成新的共享ID
	shareID := generateShareID()
	sharedFiles[shareID] = filePath
	return shareID
}

// sharedFolderHandler被修改为调用sharedFilesHandler函数
func sharedFolderHandler(w http.ResponseWriter, r *http.Request) {
	shareID := strings.TrimPrefix(r.URL.Path, "/shared-folder/")
	if shareID == "" {
		http.Error(w, "Invalid share ID", http.StatusBadRequest)
		return
	}

	fileName, ok := sharedFiles[shareID]
	if !ok {
		http.Error(w, "Invalid share ID", http.StatusBadRequest)
		return
	}

	// 调用sharedFilesHandler函数来显示文件列表，传递共享文件夹的路径
	sharedFilesHandler(w, r, fileName)
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	currentPath := r.URL.Query().Get("path")
	if strings.Contains(currentPath, "..") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	fullPath := filepath.Join(uploadDir, currentPath)

	files, err := os.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Unable to read the directory", http.StatusInternalServerError)
		return
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir() && !files[j].IsDir() {
			return true
		}
		if !files[i].IsDir() && files[j].IsDir() {
			return false
		}
		return files[i].Name() < files[j].Name()
	})

	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Pango File Manager</title>
		<link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
		<link rel="stylesheet" href="/static/css/bootstrap.min.css">
		<link rel="stylesheet" href="/static/css/codemirror.min.css">
		<link href="/static/css/bootstrap.min.css" rel="stylesheet">
		<style>
			.file-item {
				padding: 15px;
				border-bottom: 1px solid #eee;
				transition: background-color 0.3s;
			}
			.file-item:hover {
				background-color: #f8f9fa;
			}
			.btn {
				border-radius: 20px;
				padding: 5px 15px;
				margin: 2px;
				transition: all 0.3s;
			}
			.btn:hover {
				transform: translateY(-2px);
				box-shadow: 0 2px 5px rgba(0,0,0,0.2);
			}
			.btn-primary { background-color: #007bff; }
			.btn-info { background-color: #17a2b8; }
			.btn-danger { background-color: #dc3545; }
			.btn-warning { background-color: #ffc107; }
			.btn-secondary { background-color: #6c757d; }
			.btn-outline-info { 
				color: #17a2b8; 
				border-color: #17a2b8;
			}
			.btn-outline-info:hover {
				color: #fff;
				background-color: #17a2b8;
			}
			.preview-container {
				margin-top: 15px;
				margin-bottom: 15px;
			}
			.CodeMirror {
				height: 450px;
				border: 1px solid #ddd;
				border-radius: 5px;
			}
			@media (max-width: 768px) {
				.btn-group-sm > .btn {
					padding: 3px 8px;
					font-size: 0.75rem;
				}
				.file-item .row {
					flex-direction: column;
				}
				.file-item .col-md-6 {
					width: 100%%;
					margin-bottom: 10px;
				}
				.btn-group {
					display: flex;
					flex-wrap: wrap;
					justify-content: center;
				}
			}

			.card {
				background-color: #ffffff; /* 卡片背景颜色 */
				border: 1px solid #dee2e6; /* 卡片边框颜色 */
				border-radius: 10px; /* 卡片圆角 */
				padding: 20px;
				margin-bottom: 20px;
			}
			.card-title {
				font-size: 1.5rem;
				font-weight: bold;
				color: #007bff; /* 标题颜色 */
				text-transform: uppercase; /* 标题大写 */
				border-bottom: 2px solid #007bff; /* 标题底部边框 */
				padding-bottom: 10px;
				margin-bottom: 15px;
			}
			.form-control {
				border-radius: 5px; /* 输入框圆角 */
			}
			.btn-success {
				background-color: #28a745;
				border-color: #28a745;
				border-radius: 5px; /* 按钮圆角 */
				padding: 8px 16px; /* 按钮内边距 */
				font-weight: bold; /* 按钮字体加粗 */
				text-transform: uppercase; /* 按钮文本大写 */
			}
			.btn-success:hover {
				background-color: #218838;
				border-color: #1e7e34;
			}
		</style>

	</head>
	<body>
		<div class="container mt-4">
			<h1 class="mb-4 text-center text-primary">Files in %s</h1>
			<div class="row mb-4">
				<div class="col-md-6">
					<!-- Upload Files Card -->
					<div class="card shadow-sm">
						<div class="card-body">
							<h2 class="card-title">Upload Files</h2>
							<form id="uploadForm" onsubmit="return uploadFile()">
								<div class="custom-file mb-2">
									<input type="file" class="custom-file-input" name="files" id="fileInput" multiple onchange="showSelectedFiles()">
									<label class="custom-file-label" for="fileInput">Choose files</label>
								</div>
								<button type="submit" class="btn btn-primary">Upload Files</button>
							</form>
							<div id="progress" class="mt-2"></div>
							<div id="fileList" class="mt-2"></div>
						</div>
					</div>
				</div>
				<div class="col-md-6">
					<!-- Upload Folder Card -->
					<div class="card shadow-sm">
						<div class="card-body">
							<h2 class="card-title">Upload Folder</h2>
							<form id="uploadFolderForm" onsubmit="return uploadFolder()">
								<div class="custom-file mb-2">
									<input type="file" class="custom-file-input" name="folder" id="folderInput" webkitdirectory directory multiple onchange="showSelectedFolder()">
									<label class="custom-file-label" for="folderInput">Choose folder</label>
								</div>
								<button type="submit" class="btn btn-primary">Upload Folder</button>
							</form>
							<div id="folderProgress" class="mt-2"></div>
							<div id="folderList" class="mt-2"></div>
						</div>
					</div>
				</div>
			</div>
		</div>

		<script>
		function showSelectedFiles() {
			const input = document.getElementById('fileInput');
			const fileList = document.getElementById('fileList');
			fileList.innerHTML = '';

			if (input.files.length > 0) {
				const ul = document.createElement('ul');
				Array.from(input.files).forEach(file => {
					const li = document.createElement('li');
					li.textContent = file.name;
					ul.appendChild(li);
				});
				fileList.appendChild(ul);
			} else {
				fileList.textContent = 'No files selected';
			}
		}

		function showSelectedFolder() {
			const input = document.getElementById('folderInput');
			const folderList = document.getElementById('folderList');
			folderList.innerHTML = '';

			if (input.files.length > 0) {
				const ul = document.createElement('ul');
				Array.from(input.files).forEach(file => {
					const li = document.createElement('li');
					li.textContent = file.webkitRelativePath;
					ul.appendChild(li);
				});
				folderList.appendChild(ul);
			} else {
				folderList.textContent = 'No folder selected';
			}
		}
		</script>

		<script>
		function uploadFile() {
			var formData = new FormData(document.getElementById('uploadForm'));
			return uploadData(formData, '/upload?path=%s', 'progress');
		}

		function uploadFolder() {
			var formData = new FormData(document.getElementById('uploadFolderForm'));
			return uploadData(formData, '/upload?path=%s', 'folderProgress');
		}

		function uploadData(formData, url, progressId) {
			var xhr = new XMLHttpRequest();
			xhr.open('POST', url, true);
			var startTime = new Date().getTime();
			xhr.upload.onprogress = function(e) {
				if (e.lengthComputable) {
					var percentComplete = (e.loaded / e.total) * 100;
					var currentTime = new Date().getTime();
					var elapsedTime = (currentTime - startTime) / 1000;
					var uploadSpeed = e.loaded / elapsedTime;
					var remainingTime = (e.total - e.loaded) / uploadSpeed;
					
					var progressText = percentComplete.toFixed(2) + '%%';
					progressText += ' | 速度: ' + formatSize(uploadSpeed) + '/s';
					progressText += ' | 剩余时间: ' + formatTime(remainingTime);
					
					document.getElementById(progressId).innerHTML = progressText;
				}
			};
			xhr.onload = function() {
				if (this.status == 200) {
					window.location.reload();
				} else {
					alert('Upload failed: ' + this.responseText);
				}
			};
			xhr.send(formData);
			return false;
		}

		function formatSize(bytes) {
			if (bytes < 1024) return bytes + ' B';
			else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
			else if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
			else return (bytes / 1073741824).toFixed(2) + ' GB';
		}

		function formatTime(seconds) {
			if (seconds < 60) return seconds.toFixed(0) + ' 秒';
			else if (seconds < 3600) return (seconds / 60).toFixed(0) + ' 分钟';
			else return (seconds / 3600).toFixed(1) + ' 小时';
		}
		</script>
		<div class="container mt-4">
			<div class="container mt-4">
				<div class="row mb-4">
					<div class="col-md-6">
						<!-- Create New Folder Card -->
						<div class="card shadow-sm">
							<h2 class="card-title">Create New Folder</h2>
							<form action="/new-folder?path=%s" method="post" class="form-inline">
								<input type="text" name="folder_name" class="form-control mr-2" placeholder="Folder Name">
								<button type="submit" class="btn btn-success">Create Folder</button>
							</form>
						</div>
					</div>
					<div class="col-md-6">
						<!-- Create New Text File Card -->
						<div class="card shadow-sm">
							<h2 class="card-title">Create New Text File</h2>
							<form action="/new-text-file?path=%s" method="post" class="form-inline">
								<input type="text" name="file_name" class="form-control mr-2" placeholder="File Name">
								<button type="submit" class="btn btn-success">Create Text File</button>
							</form>
						</div>
					</div>
				</div>
			</div>
			<div class="file-list">
    `, currentPath, url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath))

	for i, file := range files {
		fileName := file.Name()
		filePath := filepath.Join(currentPath, fileName)
		relativeFilePath := filePath
		deletePath := url.QueryEscape(relativeFilePath)

		info, err := file.Info()
		if err != nil {
			http.Error(w, "Unable to get file info", http.StatusInternalServerError)
			return
		}
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		var fileSize string
		if file.IsDir() {
			fileSize = "N/A"
			shareID, shared := findShareIDByPath(relativeFilePath)
			shareLink := ""
			if shared {
				shareURL := fmt.Sprintf("http://%s/shared/%s", r.Host, shareID)
				shareLink = fmt.Sprintf(`<a href='#' onclick="showExistingSharePopup('%s', event)" class="btn btn-outline-info btn-sm">Shared Link</a>`, shareURL)
			}
			fmt.Fprintf(w, `
                <div class="file-item">
                    <div class="row align-items-center">
                        <div class="col-md-6 mb-2 mb-md-0">
                            <strong>[Folder] %s</strong><br>
                            <small class="text-muted">Last modified: %s</small>
                        </div>
                        <div class="col-md-6">
                            <div class="btn-group btn-group-sm d-flex flex-wrap justify-content-end" role="group">
                                <a href='/files?path=%s' class="btn btn-primary">Open</a>
                                <a href='#' onclick="showSharePopup('%s', event)" class="btn btn-info">Share Folder</a>
                                <a href='#' onclick="confirmDelete('%s')" class="btn btn-danger">Delete</a>
                                <a href='#' onclick="promptRename('%s')" class="btn btn-warning">Rename</a>
                                <a href='#' onclick="promptMove('%s')" class="btn btn-secondary">Move</a>
                                %s
                            </div>
                        </div>
                    </div>
                </div>
            `, fileName, modTime, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), shareLink)
		} else {
			fileSize = fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			downloadCount := downloadCounts[relativeFilePath]
			shareID, shared := findShareIDByPath(filePath)
			shareLink := ""
			if shared {
				shareURL := fmt.Sprintf("http://%s/shared/%s", r.Host, shareID)
				shareLink = fmt.Sprintf(`<a href='#' onclick="showExistingSharePopup('%s', event)" class="btn btn-outline-info btn-sm">Shared Link</a>`, shareURL)
			}
			directLink := generateDirectLink(filePath, r.Host)

			fmt.Fprintf(w, `
                <div class="file-item">
                    <div class="row align-items-center">
                        <div class="col-md-6 mb-2 mb-md-0">
                            <strong>%s</strong><br>
                            <small class="text-muted">Size: %s, Last modified: %s</small>
                        </div>
                        <div class="col-md-6">
                            <div class="btn-group btn-group-sm d-flex flex-wrap justify-content-end" role="group">
                                <a href='/download?file=%s' class="btn btn-primary">Download</a>
                                <a href='#' onclick="showSharePopup('%s', event)" class="btn btn-info">Share</a>
                                <a href='#' onclick="confirmDelete('%s')" class="btn btn-danger">Delete</a>
                                <a href='#' onclick="promptRename('%s')" class="btn btn-warning">Rename</a>
                                <a href='#' onclick="promptMove('%s')" class="btn btn-secondary">Move</a>
                                <a href='%s' class="btn btn-info">Direct Link</a>
                                %s
            `, fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), directLink, shareLink)

			if isMediaFile(fileName) || isJPEGFile(fileName) || isTextFile(fileName) {
				fmt.Fprintf(w, `
                                <button onclick="%s('%s', '%s')" class="btn btn-outline-secondary">Preview</button>
                `, getPreviewFunction(fileName), url.QueryEscape(relativeFilePath), "preview"+strconv.Itoa(i))
			}

			fmt.Fprintf(w, `
                            </div>
                        </div>
                    </div>
                    <small class="text-muted d-block mt-2">Download count: %d</small>
                    <div class="preview-container" id="%s"></div>
                </div>
            `, downloadCount, "preview"+strconv.Itoa(i))
		}
	}

	fmt.Fprintf(w, `
        </div>
    </div>
	<footer class="mt-5 mb-3 text-center">
        <p class="text-muted">Created by sligter | <a href="https://github.com/sligter/pango" target="_blank">GitHub</a></p>
    </footer>
		<script src="/static/jquery/jquery-3.5.1.slim.min.js"></script>
        <script src="/static/js/popper.min.js"></script>
        <script src="/static/js/bootstrap.min.js"></script>
        <script src="/static/js/codemirror.min.js"></script>
        <script src="/static/js/javascript.min.js"></script>
        <script src="/static/js/xml.min.js"></script>
        <script src="/static/js/htmlmixed.min.js"></script>
        <script src="/static/js/css.min.js"></script>
        <script src="/static/js/markdown.min.js"></script>

		<link rel="stylesheet" href="/static/css/codemirror.min.css">
		<link rel="stylesheet" href="/static/css/monokai.min.css">
		<link rel="stylesheet" href="/static/css/dracula.min.css">
		<script src="/static/js/python.min.js"></script>
		<script src="/static/js/go.min.js"></script>
<!-- 根据需要添加更多语言模式 -->
    <script>
	// 在 <script> 标签中添加以下函数
		// 保留这个函数，用于处理新的分享请求
	function showSharePopup(filePath, event) {
		// 阻止默认行为和事件冒泡
		if (event) {
			event.preventDefault();
			event.stopPropagation();
		}

		// 记录当前滚动位置
		const scrollPosition = window.pageYOffset || document.documentElement.scrollTop;

		fetch('/share?file=' + encodeURIComponent(filePath.replace(/\\/g, '/')))
			.then(response => response.json())
			.then(data => {
				showExistingSharePopup(data.url);
				// 在显示弹窗后恢复滚动位置
				window.scrollTo(0, scrollPosition);

				// 添加 Shared Link 按钮
				var shareButton = event.target;
				var buttonGroup = shareButton.closest('.btn-group');
				var sharedLinkButton = document.createElement('a');
				sharedLinkButton.href = '#';
				sharedLinkButton.onclick = function(e) { showExistingSharePopup(data.url, e); };
				sharedLinkButton.className = 'btn btn-outline-info btn-sm';
				sharedLinkButton.textContent = 'Shared Link';
				buttonGroup.appendChild(sharedLinkButton);
			})
			.catch(error => console.error('Error:', error));
	}

	function showExistingSharePopup(shareURL) {

		if (event) {
			event.preventDefault();
			event.stopPropagation();
		}
		
		// 记录当前滚动位置
    	const scrollPosition = window.pageYOffset || document.documentElement.scrollTop;

		// 创建遮罩层
		var overlay = document.createElement('div');
		overlay.style.position = 'fixed';
		overlay.style.top = '0';
		overlay.style.left = '0';
		overlay.style.width = '100%%';
		overlay.style.height = '100%%';
		overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
		overlay.style.zIndex = '999';

		var popup = document.createElement('div');
		popup.style.position = 'fixed';
		popup.style.left = '50%%';
		popup.style.top = '50%%';
		popup.style.transform = 'translate(-50%%, -50%%)';
		popup.style.backgroundColor = 'white';
		popup.style.padding = '20px';
		popup.style.borderRadius = '10px';
		popup.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
		popup.style.zIndex = '1000';
		popup.style.maxWidth = '90%%';
		popup.style.width = '400px';

		var content = document.createElement('p');
		content.textContent = '分享链接：';
		content.style.marginBottom = '10px';
		popup.appendChild(content);

		var urlInput = document.createElement('input');
		urlInput.type = 'text';
		urlInput.value = shareURL;
		urlInput.readOnly = true;
		urlInput.style.width = '100%%';
		urlInput.style.padding = '5px';
		urlInput.style.marginBottom = '15px';
		urlInput.style.border = '1px solid #ccc';
		urlInput.style.borderRadius = '4px';
		popup.appendChild(urlInput);

		var buttonContainer = document.createElement('div');
		buttonContainer.style.display = 'flex';
		buttonContainer.style.justifyContent = 'space-between';

		var copyButton = document.createElement('button');
		copyButton.textContent = '复制链接';
		copyButton.style.padding = '8px 15px';
		copyButton.style.backgroundColor = '#4CAF50';
		copyButton.style.color = 'white';
		copyButton.style.border = 'none';
		copyButton.style.borderRadius = '4px';
		copyButton.style.cursor = 'pointer';
		copyButton.onclick = function(e) {
			e.preventDefault(); // 防止页面滚动
			copyToClipboard(shareURL);
		};
		buttonContainer.appendChild(copyButton);

		var closeButton = document.createElement('button');
		closeButton.textContent = '关闭';
		closeButton.style.padding = '8px 15px';
		closeButton.style.backgroundColor = '#f44336';
		closeButton.style.color = 'white';
		closeButton.style.border = 'none';
		closeButton.style.borderRadius = '4px';
		closeButton.style.cursor = 'pointer';
		closeButton.onclick = function(e) {
			e.preventDefault(); // 防止页面滚动
			document.body.removeChild(overlay);
		};
		buttonContainer.appendChild(closeButton);

		window.scrollTo(0, scrollPosition);

		popup.appendChild(buttonContainer);
		overlay.appendChild(popup);
		document.body.appendChild(overlay);
	}

	function copyToClipboard(text) {
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).then(function() {
				showToast('链接已复制到剪贴板');
			}).catch(function(err) {
				console.error('无法复制链接: ', err);
				fallbackCopyTextToClipboard(text);
			});
		} else {
			fallbackCopyTextToClipboard(text);
		}
	}

	function fallbackCopyTextToClipboard(text) {
		var textArea = document.createElement("textarea");
		textArea.value = text;
		textArea.style.position = "fixed";
		textArea.style.top = "0";
		textArea.style.left = "0";
		textArea.style.width = "2em";
		textArea.style.height = "2em";
		textArea.style.padding = "0";
		textArea.style.border = "none";
		textArea.style.outline = "none";
		textArea.style.boxShadow = "none";
		textArea.style.background = "transparent";
		document.body.appendChild(textArea);
		textArea.focus();
		textArea.select();

		try {
			var successful = document.execCommand('copy');
			var msg = successful ? '链接已复制到剪贴板' : '无法复制链接';
			showToast(msg);
		} catch (err) {
			console.error('回退方法也无法复制: ', err);
			showToast('无法复制链接，请手动复制');
		}

		document.body.removeChild(textArea);
	}

	function showToast(message) {
		var toast = document.createElement('div');
		toast.textContent = message;
		toast.style.position = 'fixed';
		toast.style.bottom = '20px';
		toast.style.left = '50%%';
		toast.style.transform = 'translateX(-50%%)';
		toast.style.backgroundColor = 'rgba(0, 0, 0, 0.7)';
		toast.style.color = 'white';
		toast.style.padding = '10px 20px';
		toast.style.borderRadius = '5px';
		toast.style.zIndex = '2000';
		document.body.appendChild(toast);

		setTimeout(function() {
			document.body.removeChild(toast);
		}, 3000);
	}

    function confirmDelete(itemPath) {
        if (confirm("Are you sure you want to delete this item?")) {
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/delete';
            var hiddenField = document.createElement('input');
            hiddenField.type = 'hidden';
            hiddenField.name = 'item';
            hiddenField.value = itemPath;
            form.appendChild(hiddenField);
            document.body.appendChild(form);
            form.submit();
        }
    }

    function promptRename(currentPath) {
        var newName = prompt("Enter new name:");
        if (newName) {
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/rename';
            var currentPathInput = document.createElement('input');
            currentPathInput.type = 'hidden';
            currentPathInput.name = 'current_path';
            currentPathInput.value = currentPath;
            form.appendChild(currentPathInput);
            var newNameInput = document.createElement('input');
            newNameInput.type = 'hidden';
            newNameInput.name = 'new_name';
            newNameInput.value = newName;
            form.appendChild(newNameInput);
            document.body.appendChild(form);
            form.submit();
        }
    }

    function promptMove(currentPath) {
        var newPath = prompt("Enter new path:");
        if (newPath) {
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/move';
            var sourceInput = document.createElement('input');
            sourceInput.type = 'hidden';
            sourceInput.name = 'source';
            sourceInput.value = currentPath;
            form.appendChild(sourceInput);
            var targetInput = document.createElement('input');
            targetInput.type = 'hidden';
            targetInput.name = 'target';
            targetInput.value = newPath;
            form.appendChild(targetInput);
            document.body.appendChild(form);
            form.submit();
        }
    }

    function createMediaPlayer(filePath, id) {
        var playerElement = document.getElementById(id);
        if (playerElement.innerHTML !== '') {
            playerElement.innerHTML = '';
        } else {
            var fileExtension = filePath.split('.').pop().toLowerCase();
            if (fileExtension === 'mp3' || fileExtension === 'wav') {
                playerElement.innerHTML = '<audio controls preload="auto" style="width: 100%%;"><source src="/download?file=' + filePath + '" type="audio/' + fileExtension + '">Your browser does not support the audio element.</audio>';
            } else {
                playerElement.innerHTML = '<video controls preload="auto" style="width: 100%%;"><source src="/download?file=' + filePath + '" type="video/' + fileExtension + '">Your browser does not support the video element.</video>';
            }
        }
    }

    function createImagePreview(filePath, id) {
        var previewElement = document.getElementById(id);
        if (previewElement.innerHTML !== '') {
            previewElement.innerHTML = '';
        } else {
            previewElement.innerHTML = '<img src="/download?file=' + filePath + '" alt="Image preview" style="max-width: 60%%;">';
        }
    }

    function createTextPreview(filePath, id) {
        var previewElement = document.getElementById(id);
        if (previewElement.innerHTML !== '') {
            previewElement.innerHTML = '';
        } else {
            fetch('/download?file=' + filePath + '&timestamp=' + Date.now())
            .then(response => response.text())
            .then(data => {
                // 创建textarea元素
                var textarea = document.createElement('textarea');
                textarea.id = 'textarea' + id;
                previewElement.appendChild(textarea);

                // 创建保存按钮
                var saveButton = document.createElement('button');
                saveButton.innerHTML = 'Save';
                saveButton.className = 'btn btn-primary mt-2';
                saveButton.onclick = function() { saveText(filePath, id); };
                previewElement.appendChild(saveButton);

                // 初始化CodeMirror
                var editor = CodeMirror.fromTextArea(textarea, {
                    lineNumbers: true,
                    mode: getCodeMirrorMode(filePath),
                    theme: 'dracula',
                    autoCloseBrackets: true,
                    matchBrackets: true,
                    indentUnit: 4,
					autofocus: true,
                    indentWithTabs: true
                });

                // 设置编辑器内容
                editor.setValue(data);

                // 存储编辑器实例
                window['editor' + id] = editor;

				// 在创建编辑器后添加主题选择器
				var themeSelect = document.createElement('select');
				themeSelect.className = 'form-control mt-2';
				themeSelect.onchange = function() { changeTheme(id, this.value); };
				['dracula','default','monokai'].forEach(function(theme) {
					var option = document.createElement('option');
					option.value = theme;
					option.text = theme.charAt(0).toUpperCase() + theme.slice(1);
					themeSelect.appendChild(option);
				});
				previewElement.appendChild(themeSelect);
            });
        }
    }
    function getCodeMirrorMode(filePath) {
        var extension = filePath.split('.').pop().toLowerCase();
        switch (extension) {
            case 'js':
                return 'javascript';
            case 'html':
                return 'htmlmixed';
            case 'css':
                return 'css';
			case 'go':
                return 'text/x-go';
			case 'py':
                return 'python';
            case 'md':
                return 'markdown';
            default:
                return 'text/plain';
        }
    }

	function changeTheme(id, theme) {
		var editor = window['editor' + id];
		editor.setOption("theme", theme);
	}

	

    function saveText(filePath, id) {
		var editor = window['editor' + id];
		var content = editor.getValue();
		
		fetch('/save', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: 'file=' + encodeURIComponent(filePath) + '&content=' + encodeURIComponent(content)
		})
		.then(response => response.text())
		.then(data => {
			alert('File saved successfully');
		})
		.catch((error) => {
			console.error('Error:', error);
			alert('Error saving file');
		});
	}
    </script>
    `)

	if currentPath != "" {
		parentPath := filepath.Dir(currentPath)
		if parentPath == "." || parentPath == "/" {
			parentPath = ""
		}
		fmt.Fprintf(w, `<div class="mt-4"><a href='/files?path=%s' class="btn btn-secondary">Back</a></div>`, url.QueryEscape(parentPath))
	}

	fmt.Fprintf(w, `
</body>
</html>
    `)
}

func getPreviewFunction(fileName string) string {
	if isMediaFile(fileName) {
		return "createMediaPlayer"
	} else if isJPEGFile(fileName) {
		return "createImagePreview"
	} else if isTextFile(fileName) {
		return "createTextPreview"
	}
	return ""
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从表单中获取要删除的文件或文件夹的路径
	r.ParseForm()                       // 解析表单数据
	itemToDelete := r.FormValue("item") // 使用FormValue而不是URL.Query().Get
	if itemToDelete == "" {
		http.Error(w, "Item to delete is not specified", http.StatusBadRequest)
		return
	}

	// 对URL编码后的路径进行解码
	decodedPath, err := url.QueryUnescape(itemToDelete)
	if err != nil {
		http.Error(w, "Failed to decode item path", http.StatusBadRequest)
		return
	}

	// 完整的文件或文件夹路径
	fullPath := filepath.Join(uploadDir, decodedPath)

	// fmt.Println("Attempting to delete:", decodedPath)
	// fmt.Println("Full path:", fullPath)

	// 检查文件或文件夹是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		http.Error(w, "Item does not exist", http.StatusNotFound)
		return
	}

	// 删除文件或文件夹
	err = os.RemoveAll(fullPath)
	if err != nil {
		http.Error(w, "Failed to delete item", http.StatusInternalServerError)
		return
	}

	// 删除成功后重定向回文件列表
	http.Redirect(w, r, "/files?path="+url.QueryEscape(filepath.Dir(decodedPath)), http.StatusFound)
}

/*
	func findShareIDByFileName(fileName string) (string, bool) {
		for id, name := range sharedFiles {
			if name == fileName {
				return id, true
			}
		}
		return "", false
	}
*/
func findShareIDByPath(filePath string) (string, bool) {
	for id, path := range sharedFiles {
		if path == filePath {
			return id, true
		}
	}
	return "", false
}

func findPathByShareID(shareID string) (string, bool) {
	for id, path := range sharedFiles {
		if id == shareID {
			return path, true
		}
	}
	return "", false
}

func generateShareID() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// 重命名函数
func renameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析表单以获取当前项的路径和新名称
	r.ParseForm()
	currentPath := r.FormValue("current_path")
	newName := r.FormValue("new_name")

	// 检查参数是否有效
	if currentPath == "" || newName == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	decodedPath, err1 := url.QueryUnescape(currentPath)
	if err1 != nil {
		fmt.Println("Error decoding path:", err1)
		return
	}

	fullPath := filepath.Join(uploadDir, decodedPath)
	newPath := filepath.Join(uploadDir, filepath.Dir(decodedPath), newName)
	err := os.Rename(fullPath, newPath)
	// 计算完整的当前路径和目标路径
	// fullPath := filepath.Join(uploadDir, currentPath)
	// newPath := filepath.Join(uploadDir, filepath.Dir(currentPath), newName)

	// 重命名文件或文件夹

	// fmt.Println("Full path:", fullPath)
	// fmt.Println("Full path:", newPath)
	if err != nil {
		http.Error(w, "Failed to rename item", http.StatusInternalServerError)
		return
	}

	// 重命名成功后重定向回文件列表
	http.Redirect(w, r, "/files?path="+filepath.Dir(decodedPath), http.StatusFound)
}

// 文件移动函数
func moveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从表单中获取源路径和目标路径
	sourcePath := r.FormValue("source")
	targetPath := r.FormValue("target")

	// 对源路径和目标路径进行URL解码
	decodedSourcePath, err := url.QueryUnescape(sourcePath)
	if err != nil {
		http.Error(w, "Failed to decode source path", http.StatusBadRequest)
		return
	}

	decodedTargetPath, err := url.QueryUnescape(targetPath)
	if err != nil {
		http.Error(w, "Failed to decode target path", http.StatusBadRequest)
		return
	}

	// 完整的源路径和目标路径
	fullSourcePath := filepath.Join(uploadDir, decodedSourcePath)
	fullTargetPath := filepath.Join(uploadDir, decodedTargetPath, filepath.Base(decodedSourcePath))

	// 执行移动操作
	err = os.Rename(fullSourcePath, fullTargetPath)
	if err != nil {
		http.Error(w, "Failed to move item", http.StatusInternalServerError)
		return
	}

	// 移动成功后，重定向回文件列表页面
	http.Redirect(w, r, "/files?path="+url.QueryEscape(filepath.Dir(decodedTargetPath)), http.StatusFound)
}

// 直链
func generateDirectLink(filePath string, host string) string {
	directLink := fmt.Sprintf("http://%s/statics/%s", host, filePath)
	return directLink
}

// 创建新文件
func newTextFileHandler(w http.ResponseWriter, r *http.Request) {
	currentPath := r.URL.Query().Get("path") // 获取当前路径

	if r.Method == http.MethodPost {
		fileName := r.FormValue("file_name")
		if fileName == "" {
			http.Error(w, "File name cannot be empty", http.StatusBadRequest)
			return
		}

		// 创建新的文本文件
		fullPath := filepath.Join(uploadDir, currentPath, fileName)
		err := os.WriteFile(fullPath, []byte(""), 0644)
		if err != nil {
			http.Error(w, "Failed to create text file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 重定向回当前路径
		http.Redirect(w, r, "/files?path="+url.QueryEscape(currentPath), http.StatusFound)
	}
}
