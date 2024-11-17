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

	// 在程序启动时创建义上传目录
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
	// 判断是否提供域
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
		// 设 cookie 的有效期为月
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

// checkCredentials 检提供名和密码是否匹
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

	// 设置最大求体大小
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

		// 使用缓的写入器
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
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

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

	// Set the Content-Type header
	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(fileName))

	// 增加下载计数，不管是否登录都计数
	downloadCounts[fileName]++

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

	// 增加下载数，管是否登录都计数
	downloadCounts[fileName]++

	if info.IsDir() {
		http.Redirect(w, r, "/shared-folder/"+shareID, http.StatusFound)
	} else {
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

	// 统一路径分符
	decodedFileName = filepath.FromSlash(decodedFileName)

	// 构建完整的文件路径
	filePath := filepath.Join(uploadDir, decodedFileName)

	// 检查文件或目录是否存在
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File or directory not found", http.StatusNotFound)
		return
	}

	// 检查是否已经存在分享链接
	var shareID string
	var exists bool
	for id, path := range sharedFiles {
		if path == decodedFileName {
			shareID = id
			exists = true
			break
		}
	}

	// 如果不存在分享链接，则创建新的
	if !exists {
		shareID = generateShareID()
		sharedFiles[shareID] = decodedFileName
	}

	var shareURL string
	if info.IsDir() {
		shareURL = fmt.Sprintf("http://%s/shared-folder/%s", r.Host, shareID)
	} else {
		shareURL = fmt.Sprintf("http://%s/shared/%s", r.Host, shareID)
	}

	// 返回 JSON 响应，包含分享链接和是否为新创建的标志
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":     shareURL,
		"isNew":   !exists,
		"shareId": shareID,
	})
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
	// 仅检查几种常见的片文件扩展名
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
	// 确定是音频还视频文件
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
        <link rel="stylesheet" href="/static/css/all.min.css">
        <link rel="stylesheet" href="/static/css/codemirror.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .container {
                background-color: white;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                padding: 30px;
                margin-top: 30px;
            }
            .file-list-item {
                border: 1px solid #eee;
                border-radius: 10px;
                margin-bottom: 1rem;
                padding: 1rem;
                transition: all 0.3s ease;
                background-color: white;
            }
            .file-list-item:hover {
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                transform: translateY(-2px);
            }
            .file-icon {
                font-size: 2rem;
                width: 50px;
                text-align: center;
            }
            .file-info {
                flex-grow: 1;
                margin-left: 1rem;
            }
            .file-name {
                font-size: 1.1rem;
                font-weight: 500;
                margin-bottom: 0.25rem;
            }
            .file-meta {
                font-size: 0.85rem;
                color: #666;
            }
            .action-buttons {
                display: flex;
                gap: 0.3rem;  // 减按钮之间的间距
                flex-wrap: wrap;
            }
            .action-buttons .btn {
                padding: 0.3rem 0.6rem;  // 减小按钮的内边距
                border-radius: 15px;     // 稍微调整圆角
                font-weight: 500;
                display: flex;
                align-items: center;
                gap: 0.3rem;            // 减小图标和文字之间的间距
                font-size: 0.85rem;     // 减小字体大小
            }
            .action-buttons .btn i {
                font-size: 0.85rem;     // 减小图标大小
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
                .container {
                    padding: 15px;
                    margin-top: 15px;
                }
                .action-buttons {
                    justify-content: flex-start;
                }
                .action-buttons .btn {
                    padding: 0.3rem 0.8rem;
                    font-size: 0.9rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="file-list">
    `)

	// 添加返回上一级的链接
	if sharedPath != "" {
		parentPath := filepath.Dir(sharedPath)
		// 检查父目录是否超出了分享的根目录范围
		if parentPath != "." && strings.HasPrefix(parentPath, sharedPath) {
			// 获取父目录的 shareID
			parentShareID := findShareID(parentPath)
			fmt.Fprintf(w, `
                <div class="file-list-item">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center">
                            <div class="file-icon">
                                <i class="fas fa-level-up-alt fa-1x text-secondary"></i>
                            </div>
                            <div class="file-info">
                                <a href="/shared-folder/%s" class="text-decoration-none">
                                    <div class="file-name text-dark">返回上一级</div>
                                </a>
                                <div class="file-meta">上级目录</div>
                            </div>
                        </div>
                    </div>
                </div>
            `, parentShareID)
		}
	}

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
                <div class="file-list-item">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center">
                            <div class="file-icon">
                                <i class="fas fa-folder fa-1x text-warning"></i>
                            </div>
                            <div class="file-info">
                                <a href="/shared-folder/%s" class="text-decoration-none">
                                    <div class="file-name text-dark">%s</div>
                                </a>
                                <div class="file-meta">文件夹 | 修改时间: %s</div>
                            </div>
                        </div>
                        <div class="action-buttons">
                            <a href='/shared-folder/%s' class="btn btn-primary">
                                <i class="fas fa-folder-open"></i> 打开
                            </a>
                        </div>
                    </div>
                </div>
            `, shareID, fileName, modTime, shareID)
		} else {
			fileSize = fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			fmt.Fprintf(w, `
                <div class="file-list-item">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center">
                            <div class="file-icon">
                                <i class="fas %s fa-1x text-primary"></i>
                            </div>
                            <div class="file-info">
                                <div class="file-name">%s</div>
                                <div class="file-meta">大小: %s | 修改时间: %s</div>
                            </div>
                        </div>
                        <div class="action-buttons">
                            <a href='/download-share?file=%s' class="btn btn-primary">
                                <i class="fas fa-download"></i> 下载
                            </a>
            `, getFileIcon(fileName), fileName, fileSize, modTime, url.QueryEscape(relativeFilePath))

			if isMediaFile(fileName) || isJPEGFile(fileName) || isTextFile(fileName) {
				fmt.Fprintf(w, `
                        <button onclick="%s('%s', '%s')" class="btn btn-secondary">
                            <i class="fas fa-eye"></i> 预览
                        </button>
                `, getPreviewFunction(fileName), url.QueryEscape(relativeFilePath), "preview"+strconv.Itoa(i))
			}

			fmt.Fprintf(w, `
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
        // 添加 getCodeMirrorMode 函数
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
                case 'xml':
                    return 'xml';
                case 'json':
                    return { name: 'javascript', json: true };
                case 'txt':
                    return 'text/plain';
                default:
                    return 'text/plain';
            }
        }

        function createMediaPlayer(filePath, id) {
            var playerElement = document.getElementById(id);
            if (playerElement.innerHTML !== '') {
                playerElement.innerHTML = '';
            } else {
                var fileExtension = filePath.split('.').pop().toLowerCase();
                if (fileExtension === 'mp3' || fileExtension === 'wav' || fileExtension === 'm4a' || 
                    fileExtension === 'ogg' || fileExtension === 'aac' || fileExtension === 'flac') {
                    playerElement.innerHTML = '<audio controls preload="auto" style="width: 100%%;"><source src="/download-share?file=' + 
                        filePath + '" type="audio/' + fileExtension + '">Your browser does not support the audio element.</audio>';
                } else {
                    // 修改视频播放器的容器和样式
                    playerElement.innerHTML = 
                        '<div class="video-container" style="max-width: 100%%; width: 100%%; margin: 10px 0; overflow: hidden;">' +
                        '<video controls preload="auto" style="width: 100%%; max-width: 100%%; max-height: 400px; object-fit: contain; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">' +
                        '<source src="/download-share?file=' + filePath + '" type="video/' + fileExtension + '">' +
                        'Your browser does not support the video element.' +
                        '</video>' +
                        '</div>';
                }

                // 添加关闭预览的按钮
                var closeButton = document.createElement('button');
                closeButton.textContent = '关闭预览';
                closeButton.className = 'btn btn-secondary mt-2';
                closeButton.onclick = function() {
                    playerElement.innerHTML = '';
                };
                playerElement.appendChild(closeButton);
            }
        }

        function createImagePreview(filePath, id) {
				var previewElement = document.getElementById(id);
				if (previewElement.innerHTML !== '') {
					previewElement.innerHTML = '';
				} else {
					// 创建图片容器
					var imgContainer = document.createElement('div');
					//imgContainer.style.position = 'relative';
					imgContainer.style.maxWidth = '100%%';
					imgContainer.style.margin = '10px 0';

					// 创建图片元素
					var img = document.createElement('img');
					img.src = '/download-share?file=' + filePath;
					img.alt = 'Image preview';
					img.style.maxWidth = '100%%';
					img.style.height = 'auto';
					img.style.borderRadius = '4px';
					img.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';

					// 创建加载提示
					var loadingDiv = document.createElement('div');
					loadingDiv.textContent = '加载中...';
					loadingDiv.style.position = 'absolute';
					loadingDiv.style.top = 'auto';
					loadingDiv.style.left = 'auto';
					loadingDiv.style.transform = 'translate(-50%%, -50%%)';
					imgContainer.appendChild(loadingDiv);

					// 图片加载完成后移除加载提示
					img.onload = function() {
						if (loadingDiv.parentNode === imgContainer) {
							imgContainer.removeChild(loadingDiv);
						}
					};

					// 图片加载失败时显示错误信息
					img.onerror = function() {
						loadingDiv.textContent = '图片加载失败';
						loadingDiv.style.color = 'red';
					};

					imgContainer.appendChild(img);
					previewElement.appendChild(imgContainer);

					// 添加关闭预览按钮
					var closeButton = document.createElement('button');
					closeButton.textContent = '关闭预览';
					closeButton.className = 'btn btn-secondary mt-2';
					closeButton.onclick = function() {
						previewElement.innerHTML = '';
					};
					previewElement.appendChild(closeButton);
				}
			}

        function createTextPreview(filePath, id) {
            var previewElement = document.getElementById(id);
            if (previewElement.innerHTML !== '') {
                previewElement.innerHTML = '';
            } else {
                // 修改获取文件内容的URL，使用 /download 而不是 /download-share
                var encodedPath = decodeURIComponent(filePath); // 先解码
                fetch('/download-share?file=' + filePath)
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.text();
                })
                .then(data => {
                    var textarea = document.createElement('textarea');
                    textarea.id = 'textarea' + id;
                    previewElement.appendChild(textarea);

                    // 创建主题选择和控制按钮容器
                    var controlsDiv = document.createElement('div');
                    controlsDiv.className = 'editor-controls mb-2';
                    controlsDiv.style.display = 'flex';
                    controlsDiv.style.gap = '10px';
                    controlsDiv.style.alignItems = 'center';

                    // 创建主题选择下拉框
                    var themeSelect = document.createElement('select');
                    themeSelect.className = 'form-control form-control-sm';
                    themeSelect.style.width = 'auto';
                    var themes = ['default', 'dracula', 'monokai'];
                    themes.forEach(function(theme) {
                        var option = document.createElement('option');
                        option.value = theme;
                        option.text = theme.charAt(0).toUpperCase() + theme.slice(1);
                        if (theme === 'dracula') option.selected = true;
                        themeSelect.appendChild(option);
                    });

                    // 添加主题切换事件
                    themeSelect.onchange = function() {
                        editor.setOption('theme', this.value);
                    };

                    // 创建字体大小调整按钮
                    var decreaseFontBtn = document.createElement('button');
                    decreaseFontBtn.className = 'btn btn-sm btn-secondary';
                    decreaseFontBtn.innerHTML = 'A-';
                    decreaseFontBtn.onclick = function() {
                        adjustFontSize(editor, -1);
                    };

                    var increaseFontBtn = document.createElement('button');
                    increaseFontBtn.className = 'btn btn-sm btn-secondary';
                    increaseFontBtn.innerHTML = 'A+';
                    increaseFontBtn.onclick = function() {
                        adjustFontSize(editor, 1);
                    };


                    // 添加控制元素
                    controlsDiv.appendChild(document.createTextNode('主题：'));
                    controlsDiv.appendChild(themeSelect);
                    controlsDiv.appendChild(document.createTextNode('字体大小：'));
                    controlsDiv.appendChild(decreaseFontBtn);
                    controlsDiv.appendChild(increaseFontBtn);
                    //controlsDiv.appendChild(saveBtn);  // 添加保存按钮到控制栏

                    previewElement.insertBefore(controlsDiv, textarea);

                    var editor = CodeMirror.fromTextArea(textarea, {
                        lineNumbers: true,
                        mode: getCodeMirrorMode(filePath),
                        theme: 'dracula',
                        readOnly: true,  // 设置为 false 以允许编辑
                        viewportMargin: Infinity,
                        lineWrapping: true,
                        fontSize: 14, // 默认字体大小
                        value: data // 直接设置编辑器内容
                    });

                    // 确保内容被设置
                    editor.setValue(data || '');

                    // 存储编辑器实例
                    window['editor' + id] = editor;

                    // 设置初始字体大小
                    adjustFontSize(editor, 0);

                    var closeButton = document.createElement('button');
                    closeButton.textContent = '关闭预览';
                    closeButton.className = 'btn btn-secondary mt-2';
                    closeButton.onclick = function() {
                        previewElement.innerHTML = '';
                    };
                    previewElement.appendChild(closeButton);

                    // 刷新编辑器以确保内容正确显示
                    setTimeout(function() {
                        editor.refresh();
                        editor.scrollTo(0, 0); // 滚动到顶部
                    }, 10);
                })
                .catch(error => {
                    console.error('Error loading file:', error);
                    previewElement.innerHTML = '<div class="alert alert-danger">加载文件失败: ' + error.message + '</div>';
                });
            }
        }

        // 添加字体大小调整函数
        function adjustFontSize(editor, delta) {
            var fontSize = parseInt(editor.getWrapperElement().style.fontSize || '14');
            fontSize = Math.max(8, Math.min(24, fontSize + delta)); // 限制字体大小范围在 8-24px
            
            var wrapper = editor.getWrapperElement();
            wrapper.style.fontSize = fontSize + 'px';
            
            // 调整行高以持良好的可读性
            var lineHeight = fontSize * 1.5;
            wrapper.style.lineHeight = lineHeight + 'px';
            
            // 刷新编辑器以应用更改
            editor.refresh();
        }
        </script>

		<script>
		function goBack() {
			window.history.back();
		}
		</script>
    `)
}

// findShareID 通过文件路查找共享ID
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

// sharedFolderHandler被修为调用sharedFilesHandler函数
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

	// 文件排序
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir() && !files[j].IsDir() {
			return true
		}
		if !files[i].IsDir() && files[j].IsDir() {
			return false
		}
		return files[i].Name() < files[j].Name()
	})

	// 输出 HTML 头部和导航栏
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Pango File Manager</title>
		<link rel="icon" type="image/x-icon" href="/static/images/favicon.ico">
		<link href="/static/css/bootstrap.min.css" rel="stylesheet">
		<link href="/static/css/all.min.css" rel="stylesheet">
		<!-- CodeMirror CSS -->
		<link rel="stylesheet" href="/static/css/codemirror.min.css">
		<link rel="stylesheet" href="/static/css/dracula.min.css">
		<link rel="stylesheet" href="/static/css/monokai.min.css">
		<!-- CodeMirror JS -->
		<script src="/static/js/codemirror.min.js"></script>
		<script src="/static/js/javascript.min.js"></script>
		<script src="/static/js/xml.min.js"></script>
		<script src="/static/js/htmlmixed.min.js"></script>
		<script src="/static/js/css.min.js"></script>
		<script src="/static/js/markdown.min.js"></script>
		<script src="/static/js/python.min.js"></script>
		<script src="/static/js/go.min.js"></script>
		<style>
			.function-card {
				position: fixed;
				top: 60px;
				right: 20px;
				z-index: 1000;
				width: 350px;
				display: none;
			}
			.file-item {
				padding: 15px;
				border-bottom: 1px solid #eee;
				transition: background-color 0.3s;
			}
			.file-item:hover {
				background-color: #f8f9fa;
			}
			.preview-container {
				margin-top: 15px;
			}
			.btn-group .btn {
				margin: 0 2px;
			}
			.file-list-item {
				border: 1px solid #eee;
				border-radius: 10px;
				margin-bottom: 1rem;
				padding: 1rem;
				transition: all 0.3s ease;
			}
			
			.file-list-item:hover {
				box-shadow: 0 4px 8px rgba(0,0,0,0.1);
				transform: translateY(-2px);
			}
			
			.file-icon {
				font-size: 2rem;
				width: 50px;
				text-align: center;
			}
			
			.file-info {
				flex-grow: 1;
				margin-left: 1rem;
			}
			
			.file-name {
				font-size: 1.1rem;
				font-weight: 500;
				margin-bottom: 0.25rem;
			}
			
			.file-meta {
				font-size: 0.85rem;
				color: #666;
			}
			
			.action-buttons {
				display: flex;
				gap: 0.3rem;  // 减小按钮之间的间距
				flex-wrap: wrap;
			}
			
			.action-buttons .btn {
				padding: 0.3rem 0.6rem;  // 减小按钮的内边距
				border-radius: 15px;     // 稍微调整圆角
				font-weight: 500;
				display: flex;
				align-items: center;
				gap: 0.3rem;            // 减小图标和文字之间的间距
				font-size: 0.85rem;     // 减小字体大小
			}
			
			.action-buttons .btn i {
				font-size: 0.85rem;     // 减小图标大小
			}
			
			.move-form {
				display: none;
				margin-top: 1rem;
				padding: 1rem;
				background: #f8f9fa;
				border-radius: 10px;
			}
			
			.move-form.active {
				display: block;
			}
			.rename-form, .move-form {
				display: none;
				margin-top: 1rem;
				padding: 1rem;
				background: #f8f9fa;
				border-radius: 10px;
			}

			.rename-form.active, .move-form.active {
				display: block;
			}
		</style>
	</head>
	<body>
	`)

	// 输出导航栏
	fmt.Fprintf(w, `
		<nav class="navbar navbar-expand-lg navbar-light bg-light">
			<div class="container">
				<a class="navbar-brand" href="/">
					<i class="fas fa-cloud mr-2"></i>
					Pango
				</a>
				<div class="ml-auto d-flex align-items-center">
					<div class="btn-group mr-3">
						<button onclick="toggleCard('uploadFileCard')" class="btn btn-outline-primary">
							<i class="fas fa-file-upload"></i> 上传文件
						</button>
						<button onclick="toggleCard('uploadFolderCard')" class="btn btn-outline-primary">
							<i class="fas fa-folder-plus"></i> 上传文件夹
						</button>
						<button onclick="toggleCard('newFolderCard')" class="btn btn-outline-success">
							<i class="fas fa-folder"></i> 新建文件夹
						</button>
						<button onclick="toggleCard('newFileCard')" class="btn btn-outline-success">
							<i class="fas fa-file-alt"></i> 新建文本
						</button>
					</div>
					<a href="/logout" class="btn btn-outline-danger">
						<i class="fas fa-sign-out-alt"></i> 退出
					</a>
				</div>
			</div>
		</nav>
	`)

	// 输出功能卡片和面包屑导航
	fmt.Fprintf(w, `
		<div class="container mt-4">
			<!-- 功能卡片 -->
			<div id="uploadFileCard" class="function-card card">
				<div class="card-body">
					<h5 class="card-title"><i class="fas fa-file-upload"></i> 上传文件</h5>
					<form id="uploadForm" action="/upload?path=%s" method="post" enctype="multipart/form-data" 
						  onsubmit="return handleFileUpload(event, 'uploadForm')">
						<div class="custom-file mb-3">
							<input type="file" class="custom-file-input" name="files" id="fileInput" multiple
								   onchange="updateFileList(this, 'fileList')">
							<label class="custom-file-label" for="fileInput">选择文件</label>
						</div>
						<div id="fileList" class="file-list mb-3"></div>
						<div id="uploadForm-progress" class="upload-progress mb-3"></div>
						<button type="submit" class="btn btn-primary">
							<i class="fas fa-upload"></i> 上传
						</button>
					</form>
				</div>
			</div>

			<div id="uploadFolderCard" class="function-card card">
				<div class="card-body">
					<h5 class="card-title"><i class="fas fa-folder-plus"></i> 上传文件夹</h5>
					<form id="uploadFolderForm" action="/upload?path=%s" method="post" enctype="multipart/form-data"
						  onsubmit="return handleFolderUpload(event, 'uploadFolderForm')">
						<div class="custom-file mb-3">
							<input type="file" class="custom-file-input" name="folder" id="folderInput" 
								   webkitdirectory directory multiple
								   onchange="updateFileList(this, 'folderList')">
							<label class="custom-file-label" for="folderInput">选择文件夹</label>
						</div>
						<div id="folderList" class="file-list mb-3"></div>
						<div id="uploadFolderForm-progress" class="upload-progress mb-3"></div>
						<button type="submit" class="btn btn-primary">
							<i class="fas fa-upload"></i> 上传
						</button>
					</form>
				</div>
			</div>

			<div id="newFolderCard" class="function-card card">
				<div class="card-body">
					<h5 class="card-title"><i class="fas fa-folder"></i> 新文件夹</h5>
					<form action="/new-folder?path=%s" method="post">
						<div class="form-group">
							<input type="text" name="folder_name" class="form-control" placeholder="文件夹名称" required>
						</div>
						<button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> 创建</button>
					</form>
				</div>
			</div>

			<div id="newFileCard" class="function-card card">
				<div class="card-body">
					<h5 class="card-title"><i class="fas fa-file-alt"></i> 新建文本文件</h5>
					<form action="/new-text-file?path=%s" method="post">
						<div class="form-group">
							<input type="text" name="file_name" class="form-control" placeholder="文件名称" required>
						</div>
						<button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> 创建</button>
					</form>
				</div>
			</div>

			<!-- 面包屑导航 -->
			<nav aria-label="breadcrumb">
				<ol class="breadcrumb">
					<li class="breadcrumb-item"><a href="/"><i class="fas fa-home"></i></a></li>
					%s
				</ol>
			</nav>
	`, url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath), generateBreadcrumbs(currentPath))

	// 添加返回上一级按钮
	if currentPath != "" {
		parentPath := filepath.Dir(currentPath)
		if parentPath == "." {
			parentPath = ""
		}
		fmt.Fprintf(w, `
			<div class="mb-3">
				<a href="/files?path=%s" class="btn btn-secondary">
					<i class="fas fa-arrow-left"></i> 返回上一级
				</a>
			</div>
		`, url.QueryEscape(parentPath))
	}

	// 输出文件列表
	fmt.Fprintf(w, `
		<div class="card">
			<div class="card-header">
				<i class="fas fa-folder-open"></i> 文件列表
			</div>
			<div class="card-body">
				<div class="list-group">
	`)

	// 如果不是根目录，添加返回上一级
	if currentPath != "" {
		parentPath := filepath.Dir(currentPath)
		if parentPath == "." {
			parentPath = ""
		}
		fmt.Fprintf(w, `
			<div class="file-list-item">
				<div class="d-flex justify-content-between align-items-center">
					<div class="d-flex align-items-center">
						<div class="file-icon">
							<i class="fas fa-level-up-alt fa-1x text-secondary"></i>
						</div>
						<div class="file-info">
							<a href="/files?path=%s" class="text-decoration-none">
								<div class="file-name text-dark">返回上一级</div>
							</a>
							<div class="file-meta">上级目录</div>
						</div>
					</div>
				</div>
			</div>
		`, url.QueryEscape(parentPath))
	}

	// 遍历件列表
	for i, file := range files {
		fileName := file.Name()
		filePath := filepath.Join(currentPath, fileName)
		info, err := file.Info()
		if err != nil {
			continue
		}

		if file.IsDir() {
			modTime := info.ModTime().Format("2006-01-02 15:04:05")
			fmt.Fprintf(w, `
				<div class="file-list-item">
					<div class="d-flex justify-content-between align-items-center">
						<div class="d-flex align-items-center">
							<div class="file-icon">
								<i class="fas fa-folder fa-1x text-warning"></i>
							</div>
							<div class="file-info">
								<div class="file-name">%s</div>
								<div class="file-meta">文件夹 | 修改时间: %s</div>
							</div>
						</div>
						<div class="action-buttons">
							<a href="/files?path=%s" class="btn btn-primary">
								<i class="fas fa-folder-open"></i> 打开
							</a>
							<button onclick="showSharePopup('%s', event)" class="btn btn-info">
								<i class="fas fa-share"></i> 分享
							</button>
							<button onclick="toggleRenameForm('%s')" class="btn btn-warning">
								<i class="fas fa-edit"></i> 重命名
							</button>
							<button onclick="toggleMoveForm('%s')" class="btn btn-secondary">
								<i class="fas fa-arrows-alt"></i> 移动
							</button>
							<button onclick="confirmDelete('%s')" class="btn btn-danger">
								<i class="fas fa-trash"></i> 删除
							</button>
						</div>
					</div>
					<div id="rename-form-%s" class="rename-form">
						<form onsubmit="return handleRename(event, '%s')">
							<div class="input-group">
								<input type="text" class="form-control" placeholder="输入新名称" required>
								<button type="submit" class="btn btn-primary">重命名</button>
								<button type="button" class="btn btn-secondary" onclick="toggleRenameForm('%s')">取消</button>
							</div>
						</form>
					</div>
					<div id="move-form-%s" class="move-form">
						<form onsubmit="return handleMove(event, '%s')">
							<div class="input-group">
								<input type="text" class="form-control" placeholder="输入目标路径" required>
								<button type="submit" class="btn btn-primary">移动</button>
								<button type="button" class="btn btn-secondary" onclick="toggleMoveForm('%s')">取消</button>
							</div>
						</form>
					</div>
				</div>
			`, fileName, modTime,
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				url.QueryEscape(filePath), url.QueryEscape(filePath))
		} else {
			// 处理文件
			fileSize := fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			downloadCount := downloadCounts[filePath]
			fileIcon := "fa-file"

			// 根据文件类型设置不同的图标
			if isMediaFile(fileName) {
				if strings.HasSuffix(strings.ToLower(fileName), ".mp3") {
					fileIcon = "fa-file-audio"
				} else {
					fileIcon = "fa-file-video"
				}
			} else if isJPEGFile(fileName) {
				fileIcon = "fa-file-image"
			} else if isTextFile(fileName) {
				fileIcon = "fa-file-alt"
			} else if strings.HasSuffix(strings.ToLower(fileName), ".pdf") {
				fileIcon = "fa-file-pdf"
			} else if strings.HasSuffix(strings.ToLower(fileName), ".zip") ||
				strings.HasSuffix(strings.ToLower(fileName), ".rar") {
				fileIcon = "fa-file-archive"
			}

			fmt.Fprintf(w, `
				<div class="file-list-item">
					<div class="d-flex justify-content-between align-items-center">
						<div class="d-flex align-items-center">
							<div class="file-icon">
								<i class="fas %s fa-1x text-primary"></i>
							</div>
							<div class="file-info">
								<div class="file-name">%s</div>
								<div class="file-meta">大小: %s | 下载次数: %d</div>
							</div>
						</div>
						<div class="action-buttons">
							<a href="/download?file=%s" class="btn btn-primary">
								<i class="fas fa-download"></i> 下载
							</a>
							<button onclick="showSharePopup('%s', event)" class="btn btn-info">
								<i class="fas fa-share"></i> 分享
							</button>
							<button onclick="toggleRenameForm('%s')" class="btn btn-warning">
								<i class="fas fa-edit"></i> 重命名
							</button>
							<button onclick="toggleMoveForm('%s')" class="btn btn-secondary">
								<i class="fas fa-arrows-alt"></i> 移动
							</button>
							%s
							<button onclick="confirmDelete('%s')" class="btn btn-danger">
								<i class="fas fa-trash"></i> 删除
							</button>
						</div>
					</div>
					<div id="rename-form-%s" class="rename-form">
						<form onsubmit="return handleRename(event, '%s')">
							<div class="input-group">
								<input type="text" class="form-control" placeholder="输入新名称" required>
								<button type="submit" class="btn btn-primary">重命名</button>
								<button type="button" class="btn btn-secondary" onclick="toggleRenameForm('%s')">取消</button>
							</div>
						</form>
					</div>
					<div id="move-form-%s" class="move-form">
						<form onsubmit="return handleMove(event, '%s')">
							<div class="input-group">
								<input type="text" class="form-control" placeholder="输入目标路径" required>
								<button type="submit" class="btn btn-primary">移动</button>
								<button type="button" class="btn btn-secondary" onclick="toggleMoveForm('%s')">取消</button>
							</div>
						</form>
					</div>
					<div id="preview-%d" class="preview-container"></div>
				</div>
			`, fileIcon, fileName, fileSize, downloadCount,
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				url.QueryEscape(filePath), url.QueryEscape(filePath),
				getPreviewButton(fileName, filePath, i),
				url.QueryEscape(filePath),
				url.QueryEscape(fileName), url.QueryEscape(filePath),
				url.QueryEscape(filePath),
				url.QueryEscape(fileName), url.QueryEscape(filePath),
				url.QueryEscape(filePath),
				i)
		}
	}

	// 关闭文件列表
	fmt.Fprintf(w, `
			</div>
		</div>
	`)

	// 添加 JavaScript
	fmt.Fprintf(w, `
		<script src="/static/js/jquery.min.js"></script>
		<script src="/static/js/bootstrap.bundle.min.js"></script>
		<script>
			%s
		</script>
		</body>
		</html>
	`, getJavaScriptFunctions())
}

// 添加一个辅助函数来生成所有必要的 JavaScript 函数
func getJavaScriptFunctions() string {
	return `
			// 添加 getCodeMirrorMode 函定义
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
					case 'xml':
						return 'xml';
					case 'json':
						return { name: 'javascript', json: true };
					case 'txt':
						return 'text/plain';
					case 'sh':
						return 'shell';
					case 'sql':
						return 'sql';
					case 'yml':
					case 'yaml':
						return 'yaml';
					case 'rs':
						return 'rust';
					case 'cpp':
					case 'c':
					case 'h':
						return 'text/x-c++src';
					case 'java':
						return 'text/x-java';
					default:
						return 'text/plain';
				}
			}

			// 首先定义所有预览相关的函数
			function createMediaPlayer(filePath, id) {
				var playerElement = document.getElementById(id);
				if (playerElement.innerHTML !== '') {
					playerElement.innerHTML = '';
				} else {
					var fileExtension = filePath.split('.').pop().toLowerCase();
					if (fileExtension === 'mp3' || fileExtension === 'wav' || fileExtension === 'm4a' || 
						fileExtension === 'ogg' || fileExtension === 'aac' || fileExtension === 'flac') {
						playerElement.innerHTML = '<audio controls preload="auto" style="width: 100%;"><source src="/download-share?file=' + 
							filePath + '" type="audio/' + fileExtension + '">Your browser does not support the audio element.</audio>';
					} else {
						// 修改视频播放器的容器和样式
						playerElement.innerHTML = 
							'<div class="video-container" style="max-width: 100%; width: 100%; margin: 10px 0; overflow: hidden;">' +
							'<video controls preload="auto" style="width: 100%; max-width: 100%; max-height: 400px; object-fit: contain; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">' +
							'<source src="/download-share?file=' + filePath + '" type="video/' + fileExtension + '">' +
							'Your browser does not support the video element.' +
							'</video>' +
							'</div>';
					}

					// 添加关闭预览的按钮
					var closeButton = document.createElement('button');
					closeButton.textContent = '关闭预览';
					closeButton.className = 'btn btn-secondary mt-2';
					closeButton.onclick = function() {
						playerElement.innerHTML = '';
					};
					playerElement.appendChild(closeButton);
				}
			}

			function createImagePreview(filePath, id) {
				var previewElement = document.getElementById(id);
				if (previewElement.innerHTML !== '') {
					previewElement.innerHTML = '';
				} else {
					// 创建图片容器
					var imgContainer = document.createElement('div');
					imgContainer.style.position = 'relative';
					imgContainer.style.maxWidth = '100%';
					imgContainer.style.margin = '10px 0';

					// 创建图片元素
					var img = document.createElement('img');
					img.src = '/download?file=' + filePath;  // 确保URL正确编码
					img.alt = 'Image preview';
					img.style.maxWidth = '100%';
					img.style.height = 'auto';
					img.style.borderRadius = '4px';
					img.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';

					// 创建加载提示
					var loadingDiv = document.createElement('div');
					loadingDiv.textContent = '加载中...';
					loadingDiv.style.position = 'absolute';
					loadingDiv.style.top = '50%';
					loadingDiv.style.left = '50%';
					loadingDiv.style.transform = 'translate(-50%, -50%)';
					imgContainer.appendChild(loadingDiv);

					// 图片加载完成后移除加载提示
					img.onload = function() {
						if (loadingDiv.parentNode === imgContainer) {
							imgContainer.removeChild(loadingDiv);
						}
					};

					// 图片加载失败时显示错误信息
					img.onerror = function() {
						loadingDiv.textContent = '图片加载失败';
						loadingDiv.style.color = 'red';
					};

					imgContainer.appendChild(img);
					previewElement.appendChild(imgContainer);

					// 添加关闭预览按钮
					var closeButton = document.createElement('button');
					closeButton.textContent = '关闭预览';
					closeButton.className = 'btn btn-secondary mt-2';
					closeButton.onclick = function() {
						previewElement.innerHTML = '';
					};
					previewElement.appendChild(closeButton);
				}
			}

			function createVideoPlayer(filePath, id) {
				var playerElement = document.getElementById(id);
				if (playerElement.innerHTML !== '') {
					playerElement.innerHTML = '';
				} else {
					// 创建一个容器来控制视频的最大宽度
					var videoContainer = document.createElement('div');
					videoContainer.style.maxWidth = '100%';
					videoContainer.style.margin = '10px 0';
					
					var video = document.createElement('video');
					video.controls = true;
					video.preload = 'auto';
					
					video.style.width = '100%';  // 设置为100%以适应容器
					video.style.maxHeight = '400px';
					video.style.objectFit = 'contain';  // 保持视频比例
					video.style.borderRadius = '4px';
					video.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';

					var source = document.createElement('source');
					source.src = '/download-share?file=' + filePath;
					source.type = 'video/' + filePath.split('.').pop().toLowerCase();
					
					video.appendChild(source);
					videoContainer.appendChild(video);  // 将视频添加到容器中
					playerElement.appendChild(videoContainer);  // 将容器添加到预览元素中

					// 添加关闭预览的按钮
					var closeButton = document.createElement('button');
					closeButton.textContent = '关闭预览';
					closeButton.className = 'btn btn-secondary mt-2';
					closeButton.onclick = function() {
						playerElement.innerHTML = '';
					};
					playerElement.appendChild(closeButton);
				}
			}

			function createAudioPlayer(filePath, id) {
				var playerElement = document.getElementById(id);
				if (playerElement.innerHTML !== '') {
					playerElement.innerHTML = '';
				} else {
					var audio = document.createElement('audio');
					audio.controls = true;
					audio.preload = 'auto';
					audio.style.width = '100%';
					audio.style.borderRadius = '4px';
					audio.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';

					var source = document.createElement('source');
					source.src = '/download-share?file=' + filePath;
					source.type = 'audio/' + filePath.split('.').pop().toLowerCase();
					
					
					audio.appendChild(source);
					playerElement.appendChild(audio);

					// 添加关闭预览的按钮
					var closeButton = document.createElement('button');
					closeButton.textContent = '关闭预览';
					closeButton.className = 'btn btn-secondary mt-2';
					closeButton.onclick = function() {
						playerElement.innerHTML = '';
					};
					playerElement.appendChild(closeButton);
				}
			}

			// 然后是其他所有函数...
			// [其他函数保持不变]
			function toggleCard(cardId) {
				const cards = document.getElementsByClassName('function-card');
				for (let card of cards) {
					if (card.id === cardId) {
						card.style.display = card.style.display === 'none' ? 'block' : 'none';
					} else {
						card.style.display = 'none';
					}
				}
			}  // 添加缺失的闭合大括号

			// 点击页面其他地方关闭卡片
			document.addEventListener('click', function(event) {
				const cards = document.getElementsByClassName('function-card');
				const buttons = document.querySelectorAll('.btn-group button');
				
				let isButton = false;
				
				buttons.forEach(button => {
					if (button.contains(event.target)) {
						isButton = true;
					}
				});
				
				if (!isButton) {
					for (let card of cards) {
						if (!card.contains(event.target)) {
							card.style.display = 'none';
						}
					}
				}
			});  // 添加缺失的闭合括号

			// 其他已有的函数保持不变
			function confirmDelete(itemPath) {
				if (confirm("确定要删除这个项目吗？")) {
					var form = document.createElement('form');
					form.method = 'POST';
					form.action = '/delete';
					var input = document.createElement('input');
					input.type = 'hidden';
					input.name = 'item';
					input.value = itemPath;
					form.appendChild(input);
					document.body.appendChild(form);
					form.submit();
				}
			}

			function promptRename(currentPath) {
				var newName = prompt("请输入新称：");
				if (newName) {
					var form = document.createElement('form');
					form.method = 'POST';
					form.action = '/rename';
					var currentPathInput = document.createElement('input');
					currentPathInput.type = 'hidden';
					currentPathInput.name = 'current_path';
					currentPathInput.value = currentPath;
					var newNameInput = document.createElement('input');
					newNameInput.type = 'hidden';
					newNameInput.name = 'new_name';
					newNameInput.value = newName;
					form.appendChild(currentPathInput);
					form.appendChild(newNameInput);
					document.body.appendChild(form);
					form.submit();
				}
			}

			function showSharePopup(filePath, event) {
				event.preventDefault();
				fetch('/share?file=' + encodeURIComponent(filePath))
					.then(response => response.json())
					.then(data => {
						showExistingSharePopup(data.url, data.isNew);
					})
					.catch(error => console.error('Error:', error));
			}

			function showExistingSharePopup(shareURL, isNew) {
				// 记录当前滚动位
				const scrollPosition = window.pageYOffset || document.documentElement.scrollTop;

				// 创建遮罩层
				var overlay = document.createElement('div');
				overlay.style.position = 'fixed';
				overlay.style.top = '0';
				overlay.style.left = '0';
				overlay.style.width = '100%';
				overlay.style.height = '100%';
				overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
				overlay.style.zIndex = '999';

				var popup = document.createElement('div');
				popup.style.position = 'fixed';
				popup.style.left = '50%';
				popup.style.top = '50%';
				popup.style.transform = 'translate(-50%, -50%)';
				popup.style.backgroundColor = 'white';
				popup.style.padding = '20px';
				popup.style.borderRadius = '10px';
				popup.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
				popup.style.zIndex = '1000';
				popup.style.maxWidth = '90%';
				popup.style.width = '400px';

				var title = document.createElement('h5');
				title.style.marginBottom = '15px';
				title.style.color = isNew ? '#28a745' : '#17a2b8';
				title.innerHTML = isNew ? 
					'<i class="fas fa-plus-circle"></i> 新建分享链接' : 
					'<i class="fas fa-link"></i> 已存在的分享链接';
				popup.appendChild(title);

				var content = document.createElement('p');
				content.textContent = '分享链接：';
				content.style.marginBottom = '10px';
				popup.appendChild(content);

				var urlInput = document.createElement('input');
				urlInput.type = 'text';
				urlInput.value = shareURL;
				urlInput.readOnly = true;
				urlInput.style.width = '100%';
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
					e.preventDefault();
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
					e.preventDefault();
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
				toast.style.left = '50%';
				toast.style.transform = 'translateX(-50%)';
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
					showToast('文件保存成功');
					// // 重新加载文件内容
					// var encodedPath = decodeURIComponent(filePath); // 先解码
					// encodedPath = encodeURIComponent(encodedPath);  // 再编码一次	
					// fetch('/download?file=' + encodedPath)
					// .then(response => response.text())
					// .then(newContent => {
					// 	editor.setValue(newContent);
					// 	// 将光标移动到文档末尾
					// 	editor.setCursor(editor.lineCount());
					// 	// 刷新编辑器
					// 	editor.refresh();
					//})
				})
				.catch((error) => {
					console.error('Error:', error);
					showToast('保存文件失败');
				});
			}

			function createTextPreview(filePath, id) {
				var previewElement = document.getElementById(id);
				if (previewElement.innerHTML !== '') {
					previewElement.innerHTML = '';
				} else {
					// 修改获取文件内容的URL，使用 /download 而不是 /download-share
					var encodedPath = decodeURIComponent(filePath); // 先解码
					encodedPath = encodeURIComponent(encodedPath).replace(/%2B/g, '+');  // 再编码一次，但不编码特殊字符
					
					fetch('/download?file=' + encodedPath)
					.then(response => {
						if (!response.ok) {
							throw new Error('Network response was not ok');
						}
						return response.text();
					})
					.then(data => {
						// 检查数据是否为空
						

						var textarea = document.createElement('textarea');
						textarea.id = 'textarea' + id;
							previewElement.appendChild(textarea);

						// 创建主题选择和控制按容器
						var controlsDiv = document.createElement('div');
						controlsDiv.className = 'editor-controls mb-2';
						controlsDiv.style.display = 'flex';
						controlsDiv.style.gap = '10px';
						controlsDiv.style.alignItems = 'center';

						// 创建主题选择下拉框
						var themeSelect = document.createElement('select');
						themeSelect.className = 'form-control form-control-sm';
						themeSelect.style.width = 'auto';
						var themes = ['default', 'dracula', 'monokai'];
						themes.forEach(function(theme) {
							var option = document.createElement('option');
							option.value = theme;
							option.text = theme.charAt(0).toUpperCase() + theme.slice(1);
							if (theme === 'dracula') option.selected = true;
							themeSelect.appendChild(option);
						});

						// 添加主题切换事件
						themeSelect.onchange = function() {
							editor.setOption('theme', this.value);
						};

						// 创建字体大小调整按钮
						var decreaseFontBtn = document.createElement('button');
						decreaseFontBtn.className = 'btn btn-sm btn-secondary';
						decreaseFontBtn.innerHTML = 'A-';
						decreaseFontBtn.onclick = function() {
							adjustFontSize(editor, -1);
						};

						var increaseFontBtn = document.createElement('button');
						increaseFontBtn.className = 'btn btn-sm btn-secondary';
						increaseFontBtn.innerHTML = 'A+';
						increaseFontBtn.onclick = function() {
							adjustFontSize(editor, 1);
						};

						// 添加保存按钮
						var saveBtn = document.createElement('button');
						saveBtn.className = 'btn btn-sm btn-success';
						saveBtn.innerHTML = '<i class="fas fa-save"></i> 保存';
						saveBtn.onclick = function() {
							saveText(filePath, id);
						};

						

						// 添加控制元素
						controlsDiv.appendChild(document.createTextNode('主题：'));
						controlsDiv.appendChild(themeSelect);
						controlsDiv.appendChild(document.createTextNode('字体大小：'));
						controlsDiv.appendChild(decreaseFontBtn);
						controlsDiv.appendChild(increaseFontBtn);
						controlsDiv.appendChild(saveBtn);  // 添加保存按钮到控制栏

						previewElement.insertBefore(controlsDiv, textarea);

						var editor = CodeMirror.fromTextArea(textarea, {
							lineNumbers: true,
							mode: getCodeMirrorMode(filePath),
							theme: 'dracula',
							readOnly: false,  // 设置为 false 以允许编辑
							viewportMargin: Infinity,
							lineWrapping: true,
							fontSize: 14, // 默认字体大小
							value: data // 直接设置编辑器内容
						});

						// 确保内容被设置
						editor.setValue(data || '');

						// 存储编辑器实例
						window['editor' + id] = editor;

						// 设置初始字体大小
						adjustFontSize(editor, 0);

						var closeButton = document.createElement('button');
						closeButton.textContent = '关闭预览';
						closeButton.className = 'btn btn-secondary mt-2';
						closeButton.onclick = function() {
							previewElement.innerHTML = '';
						};
						previewElement.appendChild(closeButton);

						// 刷新编辑器以确保内容正确示
						setTimeout(function() {
							editor.refresh();
							editor.scrollTo(0, 0); // 滚动到顶部
						}, 10);
					})
					.catch(error => {
						console.error('Error loading file:', error);
							previewElement.innerHTML = '<div class="alert alert-danger">加载文件失败: ' + error.message + '</div>';
					});
				}
			}

			// 添加字体大小调整函数
			function adjustFontSize(editor, delta) {
				var fontSize = parseInt(editor.getWrapperElement().style.fontSize || '14');
				fontSize = Math.max(8, Math.min(24, fontSize + delta)); // 限制字体大小范围在 8-24px
				
				var wrapper = editor.getWrapperElement();
				wrapper.style.fontSize = fontSize + 'px';
				
				// 调整行高以保持良好的可读性
				var lineHeight = fontSize * 1.5;
				wrapper.style.lineHeight = lineHeight + 'px';
				
				// 刷新编辑器以应用更改
				editor.refresh();
			}

			// 在 getJavaScriptFunctions 中添加以下函数
			function uploadData(formData, url, progressId) {
				var xhr = new XMLHttpRequest();
				xhr.open('POST', url, true);
				var startTime = new Date().getTime();
				var fileList = document.getElementById(progressId);
				var files = formData.getAll('files').length > 0 ? formData.getAll('files') : formData.getAll('folder');
				var totalSize = 0;
				var uploadedSize = 0;
				
				// 计算总大小
				files.forEach(function(file) {
					totalSize += file.size;
				});

				// 创建进度显示容器
				fileList.innerHTML = '<div class="upload-total-progress mb-3">' +
					'<strong>总进度：</strong><div class="progress-text">准备上传...</div></div>';
				
				// 为每个文件创建进度条
				files.forEach(function(file, index) {
					var fileDiv = document.createElement('div');
					fileDiv.className = 'file-upload-progress mb-2';
					fileDiv.innerHTML = '<div class="file-info">' +
						'<span class="file-name">' + file.name + '</span>' +
						'<span class="file-size">(' + formatSize(file.size) + ')</span>' +
						'</div>' +
						'<div class="progress-info">' +
						'<div class="progress-text">等待上传...</div>' +
						'<div class="speed-text"></div>' +
						'<div class="time-text"></div>' +
						'</div>';
					fileList.appendChild(fileDiv);
				});

				xhr.upload.onprogress = function(e) {
					if (e.lengthComputable) {
						var currentTime = new Date().getTime();
						var elapsedTime = (currentTime - startTime) / 1000;
						var uploadSpeed = e.loaded / elapsedTime;
						var remainingTime = (totalSize - e.loaded) / uploadSpeed;
						var percentComplete = (e.loaded / e.total) * 100;

						// 更新进度
						var totalProgressDiv = fileList.querySelector('.upload-total-progress .progress-text');
						totalProgressDiv.innerHTML = 
							percentComplete.toFixed(2) + '% | ' +
							'速度: ' + formatSize(uploadSpeed) + '/s | ' +
							'剩余时间: ' + formatTime(remainingTime);

						// 计算每个文件的进度
						var currentFileIndex = Math.floor((e.loaded / e.total) * files.length);
						var currentFileProgress = (e.loaded % (e.total / files.length)) / (e.total / files.length) * 100;
						
						// 更新文件进度显示
						var fileProgressDivs = fileList.querySelectorAll('.file-upload-progress');
						fileProgressDivs.forEach(function(div, index) {
							var progressText = div.querySelector('.progress-text');
							var speedText = div.querySelector('.speed-text');
							var timeText = div.querySelector('.time-text');

							if (index < currentFileIndex) {
								// 已完成的文件
								progressText.textContent = '100% - 已完成';
								speedText.textContent = '';
								timeText.textContent = '';
								div.classList.add('completed');
							} else if (index === currentFileIndex) {
								// 当前正在上传的文件
								progressText.textContent = currentFileProgress.toFixed(2) + '%';
								speedText.textContent = '速度: ' + formatSize(uploadSpeed) + '/s';
								timeText.textContent = '剩余时间: ' + formatTime(remainingTime);
								div.classList.add('uploading');
							} else {
								// 等待上传的文件
								progressText.textContent = '等待上传...';
								speedText.textContent = '';
								timeText.textContent = '';
							}
						});
					}
				};

				xhr.onload = function() {
					if (this.status == 200) {
						fileList.innerHTML += '<div class="alert alert-success mt-3">上传完成！</div>';
						setTimeout(function() {
							window.location.reload();
						}, 1000);
					} else {
						fileList.innerHTML += '<div class="alert alert-danger mt-3">上传失败: ' + this.responseText + '</div>';
					}
				};

				xhr.onerror = function() {
					fileList.innerHTML += '<div class="alert alert-danger mt-3">上传出错，请重试</div>';
				};

				xhr.send(formData);
				return false;
			}

			// 添加相关的 CSS 样式
			const style = document.createElement('style');
			style.textContent = '.file-upload-progress {' +
				'background: #f8f9fa;' +
				'padding: 10px;' +
				'border-radius: 4px;' +
				'margin-bottom: 10px;' +
				'}' +
				'.file-upload-progress.completed {' +
				'background: #d4edda;' +
				'}' +
				'.file-upload-progress.uploading {' +
				'background: #cce5ff;' +
				'}' +
				'.file-info {' +
				'margin-bottom: 5px;' +
				'}' +
				'.file-name {' +
				'font-weight: 500;' +
				'}' +
				'.file-size {' +
				'color: #6c757d;' +
				'margin-left: 10px;' +
				'}' +
				'.progress-info {' +
				'display: flex;' +
				'justify-content: space-between;' +
				'font-size: 0.9em;' +
				'color: #495057;' +
				'}' +
				'.upload-total-progress {' +
				'background: #e9ecef;' +
				'padding: 10px;' +
				'border-radius: 4px;' +
				'margin-bottom: 15px;' +
				'}';
			document.head.appendChild(style);

			function formatSize(bytes) {
				if (bytes === 0) return '0 B';
				var k = 1024;
				var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
				var i = Math.floor(Math.log(bytes) / Math.log(k));
				return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
			}

			function formatTime(seconds) {
				if (seconds === Infinity || isNaN(seconds)) return '计算中...';
				if (seconds < 60) return seconds.toFixed(1) + '秒';
				if (seconds < 3600) return Math.floor(seconds / 60) + '分' + Math.floor(seconds % 60) + '秒';
				return Math.floor(seconds / 3600) + '时' + Math.floor((seconds % 3600) / 60) + '分';
			}

			// 修改文件上传处理函数
			function handleFileUpload(event, formId) {
				event.preventDefault();
				var form = document.getElementById(formId);
				var formData = new FormData(form);
				var progressId = formId + '-progress';
				
				// 创建或获取进度显示元素
				var progressDiv = document.getElementById(progressId);
				if (!progressDiv) {
					progressDiv = document.createElement('div');
					progressDiv.id = progressId;
					progressDiv.className = 'upload-progress';
					form.appendChild(progressDiv);
				}
				
				progressDiv.innerHTML = '准备上传...';
				return uploadData(formData, form.action, progressId);
			}

			// 修改文件上传处理函数
			function handleFolderUpload(event, formId) {
				event.preventDefault();
				var form = document.getElementById(formId);
				var formData = new FormData(form);
				var progressId = formId + '-progress';
				
				// 创建或获取进度显示元素
				var progressDiv = document.getElementById(progressId);
				if (!progressDiv) {
					progressDiv = document.createElement('div');
					progressDiv.id = progressId;
					progressDiv.className = 'upload-progress';
					form.appendChild(progressDiv);
				}
				
				progressDiv.innerHTML = '准备上传...';
				return uploadData(formData, form.action, progressId);
			}

			// 在 getJavaScriptFunctions 中添加以下函数
			function updateFileList(input, listId) {
				var fileList = document.getElementById(listId);
				fileList.innerHTML = '';
				
				var files = input.files;
				var totalSize = 0;
				
				for (var i = 0; i < files.length; i++) {
					var file = files[i];
					totalSize += file.size;
					
					var item = document.createElement('div');
					item.className = 'file-list-item mb-2';
					
					var nameSpan = document.createElement('span');
					nameSpan.className = 'file-name';
					nameSpan.textContent = file.name;
					
					var sizeSpan = document.createElement('span');
					sizeSpan.className = 'file-size text-muted ml-2';
					sizeSpan.textContent = formatSize(file.size);
					
					item.appendChild(nameSpan);
					item.appendChild(sizeSpan);
					fileList.appendChild(item);
				}
				
				// 显示总文件数和总大小
				var summaryDiv = document.createElement('div');
				summaryDiv.className = 'upload-summary mt-2';
				summaryDiv.innerHTML = '<strong>总计:</strong> ' + files.length + ' 个文件, ' +
									'<strong>总大小:</strong> ' + formatSize(totalSize);
				fileList.appendChild(summaryDiv);
				
				// 更新文件选择框的标签
				var label = input.nextElementSibling;
				if (files.length > 0) {
					label.textContent = files.length + ' 个文件已选择';
				} else {
					label.textContent = '选择文件';
				}
			}

			// 在 getJavaScriptFunctions 函数中添加以下代码
			// 在其他 JavaScript 函数的后面添加

			// ... 他 JavaScript 函数 ...

			function toggleMoveForm(filePath) {
				var encodedPath = decodeURIComponent(filePath); // 先解码
				var fileName = encodedPath.replace(/\\/g, '/').split('/').pop();
				var formId = 'move-form-' + fileName;
				var form = document.getElementById(formId);
				if (!form) {
					console.error('Move form not found:', formId);
					return;
				}
				if (form.classList.contains('active')) {
					form.classList.remove('active');
				} else {
					// 关闭其他所有打开的移动表单
					document.querySelectorAll('.move-form.active').forEach(function(activeForm) {
						activeForm.classList.remove('active');
					});
					form.classList.add('active');
				}
			}

			function handleMove(event, sourcePath) {
				event.preventDefault();
				var form = event.target;
				var targetPath = form.querySelector('input').value;
				
				// 创建表单数据
				var formData = new FormData();
				formData.append('source', sourcePath);
				formData.append('target', targetPath);
				
				// 发送 POST 请求
				fetch('/move', {
					method: 'POST',
					body: formData
				}).then(response => {
					if (response.ok) {
						window.location.reload();
					} else {
						alert('移动失败，请重试');
					}
				}).catch(error => {
					console.error('Error:', error);
					alert('移动失败，请重试');
				});
				
				return false;
			}

			// ... 其他 JavaScript 函数 ...

			function toggleRenameForm(filePath) {
				var encodedPath = decodeURIComponent(filePath); // 先解码
				var fileName = encodedPath.replace(/\\/g, '/').split('/').pop();
				var formId = 'rename-form-' + fileName;
				var form = document.getElementById(formId);
				if (!form) {
					console.error('Rename form not found:', formId);
					return;
				}
				if (form.classList.contains('active')) {
					form.classList.remove('active');
				} else {
					// 关闭其他所有打开的重命名表单
					document.querySelectorAll('.rename-form.active').forEach(function(activeForm) {
						activeForm.classList.remove('active');
					});
					// 设置默认文件名
					form.querySelector('input').value = fileName;
					form.classList.add('active');
				}
			}

			function handleRename(event, sourcePath) {
				event.preventDefault();
				var form = event.target;
				var newName = form.querySelector('input').value;
				
				if (!newName) {
					alert('文件名不能为空');
					return false;
				}
				
				// 创建 FormData 对象并添加数据
				var formData = new FormData();
				formData.append('current_path', sourcePath);
				formData.append('new_name', newName);
				
				// 调试输出
				console.log('Renaming:', {
					current_path: sourcePath,
					new_name: newName
				});
				
				fetch('/rename', {
					method: 'POST',
					body: formData
				}).then(response => {
					if (response.ok) {
						window.location.reload();
					} else {
						response.text().then(text => {
							alert('重命名失败: ' + text);
						});
					}
				}).catch(error => {
					console.error('Error:', error);
					alert('重命名失败，请重试');
				});
				
				return false;
			}
		`
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

	// 表单中获取删除的文件或文件夹的路径
	r.ParseForm()                       // 解析表单数据
	itemToDelete := r.FormValue("item") // 使用FormValue而不是URL.Query().Get
	if itemToDelete == "" {
		http.Error(w, "Item to delete is not specified", http.StatusBadRequest)
		return
	}

	// 对URL编码的路径进行解码
	decodedPath, err := url.QueryUnescape(itemToDelete)
	if err != nil {
		http.Error(w, "Failed to decode item path", http.StatusBadRequest)
		return
	}

	// 整的文件或件夹路径
	fullPath := filepath.Join(uploadDir, decodedPath)

	// fmt.Println("Attempting to delete:", decodedPath)
	// fmt.Println("Full path:", fullPath)

	// 检文件或文件夹是否存在
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

// ��改重命名处理函数
func renameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析表单数据
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// 获取表单数据
	currentPath := r.FormValue("current_path")
	decodedPath, err := url.QueryUnescape(currentPath)
	if err != nil {
		http.Error(w, "Failed to decode current path", http.StatusBadRequest)
		return
	}
	newName := r.FormValue("new_name")
	decodedNewName, err := url.QueryUnescape(newName)
	if err != nil {
		http.Error(w, "Failed to decode new name", http.StatusBadRequest)
		return
	}

	// 调试输出
	// log.Printf("Rename request - Current Path: %s, New Name: %s", decodedPath, decodedNewName)

	// 检查参数是否有效
	if currentPath == "" || newName == "" {
		http.Error(w, "Missing parameters: current_path or new_name is empty", http.StatusBadRequest)
		return
	}
	//获取当前文件所在的目录
	dir := filepath.Dir(decodedPath)
	// 构建新的完整路径
	oldPath := filepath.Join(uploadDir, decodedPath)
	newPath := filepath.Join(uploadDir, dir, decodedNewName)

	// 检查源文件是否存在
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		http.Error(w, "Source file does not exist: "+oldPath, http.StatusBadRequest)
		return
	}

	// 检查目标文件是否已存在
	if _, err := os.Stat(newPath); err == nil {
		http.Error(w, "Destination file already exists: "+newPath, http.StatusBadRequest)
		return
	}

	// 执行重命名操作
	if err := os.Rename(oldPath, newPath); err != nil {
		http.Error(w, "Failed to rename file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 重命名成功，返回成功状态
	w.WriteHeader(http.StatusOK)
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

		// 创新的文本文件
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

func generateBreadcrumbs(path string) string {
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	var breadcrumbs []string
	currentPath := ""

	for i, part := range parts {
		if part == "" {
			continue
		}
		currentPath += "/" + part
		if i == len(parts)-1 {
			breadcrumbs = append(breadcrumbs, fmt.Sprintf(`<li class="breadcrumb-item active">%s</li>`, part))
		} else {
			breadcrumbs = append(breadcrumbs, fmt.Sprintf(`<li class="breadcrumb-item"><a href="/files?path=%s">%s</a></li>`,
				url.QueryEscape(currentPath), part))
		}
	}

	return strings.Join(breadcrumbs, "")
}

// 添加一个辅助函数来生成预览按钮的 HTML
func getPreviewButton(fileName, filePath string, index int) string {
	if isMediaFile(fileName) || isJPEGFile(fileName) || isTextFile(fileName) {
		return fmt.Sprintf(`
				<button onclick="%s('%s', 'preview-%d')" class="btn btn-secondary">
					<i class="fas fa-eye"></i> 预览
				</button>
			`, getPreviewFunction(fileName), url.QueryEscape(filePath), index)
	}
	return ""
}

// 添加新的辅助函数来获取文件图标
func getFileIcon(fileName string) string {
	if isMediaFile(fileName) {
		if strings.HasSuffix(strings.ToLower(fileName), ".mp3") {
			return "fa-file-audio"
		}
		return "fa-file-video"
	} else if isJPEGFile(fileName) {
		return "fa-file-image"
	} else if isTextFile(fileName) {
		return "fa-file-alt"
	} else if strings.HasSuffix(strings.ToLower(fileName), ".pdf") {
		return "fa-file-pdf"
	} else if strings.HasSuffix(strings.ToLower(fileName), ".zip") ||
		strings.HasSuffix(strings.ToLower(fileName), ".rar") {
		return "fa-file-archive"
	}
	return "fa-file"
}
