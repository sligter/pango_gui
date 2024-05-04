package server

import (
	"context"
	"embed"
	"encoding/hex"
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
	"time"

	"github.com/gorilla/websocket"
)

var (
	uploadDir      string
	sharedFiles    = make(map[string]string)
	users          map[string]string         // 用户名:密码映射，生产环境中应使用加密密码
	sessions       = make(map[string]string) // 会话ID和用户名的映射
	downloadCounts = make(map[string]int)    //统计下载次数
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

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
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
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
		Addr:    listenAddress, // or domain:port based on earlier logic
		Handler: mux,           // Use the ServeMux we created
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

//go:embed static/images/backup-background.jpg
var backupBackgroundImage embed.FS

func loginFormHandler(w http.ResponseWriter, r *http.Request) {
	if isLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// 获取本地图片文件的URL
	imageURL := "/static/images/backup-background.jpg"
	tmpl := template.Must(template.New("login-form").Parse(`
	<!DOCTYPE html>
	<html>
	<head>
		<title>Login Page</title>
		<style>
			html {
				height: 100%;
			}
			body {
				min-height: 100%;
				margin: 0;
				padding: 0;
				background-image: url('{{ .BackgroundImageURL }}?{{ .RandomValue }}');
				background-size: cover;
				background-position: center;
				background-repeat: no-repeat;
				font-family: Arial, sans-serif;
				display: flex;
				justify-content: center;
				align-items: center;
				flex-direction: column;
			}
	
			.login-container {
				width: 100%;
				max-width: 400px;
				margin: 100px auto;
				padding: 20px;
				background-color: rgba(0, 0, 0, 0.5);
				border-radius: 5px;
				box-shadow: 0 2px 5px rgba(0,0,0,0.2);
			}
	
			h1 {
				text-align: center;
				color: white;
			}
	
			form {
				display: flex;
				flex-direction: column;
				gap: 10px;
			}
	
			input[type="text"],
			input[type="password"] {
				padding: 10px;
				border: 1px solid #ddd;
				border-radius: 3px;
				font-size: 16px;
			}
	
			input[type="submit"] {
				padding: 12px;
				border: none;
				border-radius: 3px;
				background-color: rgba(0, 0, 0, 0.5);
				color: white;
				font-size: 16px;
				cursor: pointer;
			}
	
			input[type="submit"]:hover {
				background-color: #4cae4c;
			}
		</style>
	</head>
	<body>
		<div class="login-container">
			<h1>Login</h1>
			<form action="/login-submit" method="post">
				<input type="text" name="username" placeholder="Username">
				<input type="password" name="password" placeholder="Password">
				<input type="submit" value="Login">
			</form>
		</div>
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

	// 处理文件上传
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 限制最大上传文件大小为10MB
		http.Error(w, "File too large.", http.StatusBadRequest)
		return
	}

	// 处理多文件上传
	files := r.MultipartForm.File["files"]
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			http.Error(w, "Unable to open the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		filePath := filepath.Join(fullPath, filepath.Base(fileHeader.Filename))
		dst, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Unable to create the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Unable to save the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 处理文件夹上传
	folders := r.MultipartForm.File["folder"]
	for _, folderHeader := range folders {
		// Open the file header to get the file part.
		file, err := folderHeader.Open()
		if err != nil {
			http.Error(w, "Unable to open the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// The folderHeader.Filename will contain the relative path of the file
		// including any subdirectories within the uploaded folder. We need to
		// create these subdirectories within the server's file system.
		relativePath := filepath.ToSlash(folderHeader.Filename) // Ensure we have forward slashes
		filePath := filepath.Join(fullPath, relativePath)

		// Create any necessary directories for the file path
		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			http.Error(w, "Unable to create directory for file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Create the destination file on the server
		dst, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Unable to create the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		// Copy the uploaded file to the destination file
		if _, err := io.Copy(dst, file); err != nil {
			http.Error(w, "Unable to save the file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/files?path="+url.QueryEscape(currentPath), http.StatusFound)
	//fmt.Fprintf(w, "File uploaded successfully: %s", fullPath)
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

func shareHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "No file name specified", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(uploadDir, fileName)
	info, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File or directory not found", http.StatusNotFound)
		return
	}

	shareID := generateShareID()
	sharedFiles[shareID] = fileName

	var shareURL string
	if info.IsDir() {
		// 如果是文件夹，生成指向共享文件夹处理函数的链接
		shareURL = fmt.Sprintf("http://%s/shared-folder/%s", r.Host, shareID)
	} else {
		// 如果是文件，生成指向共享文件下载处理函数的链接
		shareURL = fmt.Sprintf("http://%s/shared/%s", r.Host, shareID)
	}

	fmt.Fprintf(w, "Shared successfully. Access at \n%s ", shareURL)
}

func isMediaFile(fileName string) bool {
	// 这里我们仅检查几种常见的媒体文件扩展名
	mediaExtensions := []string{".mp4", ".mp3", ".avi", ".wav", ".mov", ".ts", ".m4a", ".amr", ".flac", ".aac", ".mkv"}
	for _, ext := range mediaExtensions {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			return true
		}
	}
	return false
}

func isJPEGFile(fileName string) bool {
	// 这里我们仅检查几种常见的图片文件扩展名
	jpgExtensions := []string{".jpg", ".png", ".jpeg", ".tif", ".gif", ".ico", ".bmp"}
	for _, ext := range jpgExtensions {
		if strings.HasSuffix(strings.ToLower(fileName), ext) {
			return true
		}
	}
	return false
}

func isTextFile(fileName string) bool {
	// 这里我们仅检查几种常见的文本文件扩展名
	textExtensions := []string{".txt", ".md", ".csv", ".json", ".xml", ".html", ".js", ".css", ".py", ".java", ".c", ".cpp", ".sh", ".json", ".go", ".R", ".rs"}
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

	fmt.Fprintf(w, "<h1>Shared Files in %s</h1>", sharedPath)
	for i, file := range files {
		fileName := file.Name()
		filePath := filepath.Join(sharedPath, fileName)
		relativeFilePath := filePath // 这是相对于uploads的路径

		info, err := file.Info()
		if err != nil {
			http.Error(w, "Unable to get file info", http.StatusInternalServerError)
			return
		}
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		var fileSize string
		if file.IsDir() {
			fileSize = "N/A"
			// 文件夹，提供链接到该文件夹
			// 找到共享ID
			shareID := findShareID(filePath)
			fmt.Fprintf(w, "<p>[Folder] %s (Last modified: %s) - <a href='/shared-folder/%s'>Open</a></p>", fileName, modTime, shareID)
			// fmt.Fprintf(w, "<p>[Folder] %s (Last modified: %s) - <a href='/shared-folder/%s'>Open</a></p>", fileName, modTime, url.QueryEscape(relativeFilePath))
		} else {
			fileSize = fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			if isMediaFile(fileName) {
				mediaPlayerButton := generateMediaPlayer(relativeFilePath, "player"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download-share?file=%s'>Download</a>%s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), mediaPlayerButton)
			} else if isJPEGFile(fileName) {
				imagePreviewButton := generateImagePreview(relativeFilePath, "preview"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download-share?file=%s'>Download</a>%s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), imagePreviewButton)
			} else if isTextFile(fileName) {
				textPreviewButton := generateTextPreview(relativeFilePath, "text"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download-share?file=%s'>Download</a>%s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), textPreviewButton)
			} else {
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download-share?file=%s'>Download</a>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath))
			}
			// 文件，提供下载链接
			// fmt.Fprintf(w, "<p>%s (Last modified: %s) - <a href='/shared/%s'>Download</a></p>", fileName, modTime, url.QueryEscape(relativeFilePath))
		}
	}
	fmt.Fprintf(w, `
<script>
function createAudioPlayer(filePath, id) {
	var playerElement = document.getElementById(id);
	if (playerElement.innerHTML !== '') {
		// 如果已经创建了播放器，那么停止播放并隐藏
		playerElement.innerHTML = '';
	} else {
		// 否则，创建新的播放器，但不自动加载媒体
		playerElement.innerHTML = '<audio controls preload="auto" style="max-width: 80vw; max-height: 500px;"><source src="/download-share?file=' + filePath + '" type="audio/mpeg">Your browser does not support the audio element.</audio>';
	}
}
	
function createVideoPlayer(filePath, id) {
	var playerElement = document.getElementById(id);
	if (playerElement.innerHTML !== '') {
		// 如果已经创建了播放器，那么停止播放并隐藏
		playerElement.innerHTML = '';
	} else {
		// 否则，创建新的播放器，但不自动加载媒体
		playerElement.innerHTML = '<video controls preload="auto" style="max-width: 80vw; max-height: 500px;"><source src="/download-share?file=' + filePath + '" type="video/mp4">Your browser does not support the video element.</video>';
	}
}
	

function createImagePreview(filePath, id) {
    var previewElement = document.getElementById(id);
    if (previewElement.innerHTML !== '') {
        // 如果已经创建了预览，那么清除预览
        previewElement.innerHTML = '';
    } else {
        // 否则，创建新的预览
        // 添加了style属性，设定了最大宽度和最大高度，图片会自动缩放以适应这个尺寸，同时保持其原始的长宽比
        previewElement.innerHTML = '<img src="/download-share?file=' + filePath + '" alt="Image preview" style="max-width: 500px; max-height: 500px;">';
    }
}

function createTextPreview(filePath, id) {
    var previewElement = document.getElementById(id);
    if (previewElement.innerHTML !== '') {
        // 如果已经创建了预览，那么清除预览
        previewElement.innerHTML = '';
    } else {
        // 否则，发送请求获取文件内容
        fetch('/download-share?file=' + filePath)
            .then(response => response.text())
            .then(data => {
                // 创建一个textarea元素，用户可以在这个元素中预览内容
                previewElement.innerHTML = '<textarea id="textarea' + id + '" style="width: 80vw; height: 500px;">' + data + '</textarea>';
            });
    }
}

</script>	
`)
	// 添加返回上一级文件夹的链接

	if sharedPath != "" {
		// 获取sharedPath的绝对路径
		absoluteSharedPath, err := filepath.Abs(sharedPath)
		if err != nil {
			// 处理错误，例如显示错误信息或记录日志
			return
		}

		// 确保sharedPath是在uploadDir目录下
		if !strings.HasPrefix(absoluteSharedPath, uploadDir) {
			// 如果不是，则可能需要处理这种情况，例如显示错误信息或者重定向到安全的地方
			return
		}

		// 获取sharedPath的父目录
		parentPath := filepath.Dir(sharedPath)
		if parentPath == "." || parentPath == "/" {
			parentPath = ""
		} else {
			// 确保父路径是相对于uploadDir的相对路径
			parentPath = filepath.ToSlash(parentPath)
		}

		// 使用父目录的共享ID
		parentShareID, found := findShareIDByPath(parentPath)
		if found {
			// 确保父共享ID对应的路径是sharedPath的直接父路径
			parentSharedPath, _ := findPathByShareID(parentShareID)
			if filepath.Dir(absoluteSharedPath) == filepath.Clean(parentSharedPath) {
				fmt.Fprintf(w, "<a href='/shared-folder/%s'>Back</a><br>", parentShareID)
			} else {
				// 如果父共享ID对应的不是直接父路径，则不显示返回链接
				// 可以选择不做任何操作，或者提供其他导航选项
			}
		} else {
			// 如果找不到父目录的共享ID，可能需要处理这种情况
			// 比如显示错误信息或者提供返回到根目录的链接
		}
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
	// 从URL查询参数中获取当前文件夹路径

	currentPath := r.URL.Query().Get("path")
	// 检查路径是否包含连续的 `.`
	if strings.Contains(currentPath, "..") {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	fullPath := filepath.Join(uploadDir, currentPath)
	// 添加上传文件和创建新文件夹的表单
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html lang="en">
<head>
	<link rel="stylesheet" href="/static/bootstrap/css/bootstrap.min.css">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pango</title>
</head>
<body>
    <div class="container">
        <h2 class="mt-16">Upload Files</h2>
        <form action="/upload?path=%s" method="post" enctype="multipart/form-data" class="mb-auto">
			<div class="custom-file">
				<input type="file" class="custom-file-input" name="files" multiple>
				<label class="custom-file-label" for="customFile">Choose files</label>
			</div>
			<button type="submit" class="btn btn-primary mt-2">Upload Files</button>
    	</form>

        <h2>Upload Folder</h2>
        <form action="/upload?path=%s" method="post" enctype="multipart/form-data" class="mb-3">
            <div class="custom-file">
                <input type="file" class="custom-file-input" name="folder" webkitdirectory directory multiple>
                <label class="custom-file-label" for="customFile">Choose folder</label>
            </div>
            <button type="submit" class="btn btn-primary mt-2">Upload Folder</button>
        </form>

        <h2>Create New Folder</h2>
        <form action="/new-folder?path=%s" method="post" class="mb-3">
            <input type="text" name="folder_name" class="form-control" placeholder="Folder Name">
            <button type="submit" class="btn btn-success mt-2">Create Folder</button>
        </form>

		<h2>Create New Text File</h2>
			<form action="/new-text-file?path=%s" method="post" class="mb-3">
				<input type="text" name="file_name" class="form-control" placeholder="File Name">
				<button type="submit" class="btn btn-success mt-2">Create Text File</button>
		</form>

    </div>
</body>
</html>
`, url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath), url.QueryEscape(currentPath))

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

	fmt.Fprintf(w, "<h1>Files in %s</h1>", currentPath)
	for i, file := range files {
		fileName := file.Name()
		filePath := filepath.Join(currentPath, fileName)
		relativeFilePath := filePath // 这是相对于uploads的路径
		// 为删除操作生成URL路径
		deletePath := url.QueryEscape(relativeFilePath)

		// Get the last modification time

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
				shareLink = fmt.Sprintf(" - <a href='http://%s/shared/%s'>Shared Link</a>", r.Host, shareID)
			}
			fmt.Fprintf(w, "<p>[Folder] %s (Last modified: %s) - <a href='/files?path=%s'>Open</a> - <a href='/share?file=%s'>Share Folder</a>%s - <a href='#' onclick=\"confirmDelete('%s')\">Delete</a> - <a href='#' onclick=\"promptRename('%s')\">Rename</a></p> - <form action='/move' method='post'><input type='hidden' name='source' value='%s'><input type='text' name='target' placeholder='Enter target path'><input type='submit' value='Move'></form>", fileName, modTime, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), shareLink, deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath))

			// 文件夹，提供链接到该文件夹，并添加删除链接
			// fmt.Fprintf(w, "<p>[Folder] %s (Last modified: %s) - <a href='/files?path=%s'>Open</a> - <a href='/share?file=%s'>Share Folder</a> - <a href='#' onclick=\"confirmDelete('%s')\">Delete</a></p>", fileName, modTime, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), deletePath)

			//fmt.Fprintf(w, "<p>[Folder] %s (Last modified: %s) - <a href='/files?path=%s'>Open</a> - <a href='#' onclick=\"confirmDelete('%s')\">Delete</a></p>", fileName, modTime, url.QueryEscape(relativeFilePath), deletePath)
		} else {
			directLink := generateDirectLink(filePath, r.Host) // 为文件生成直链
			fileSize = fmt.Sprintf("%.2f KB", float64(info.Size())/1024)
			//统计下载次数
			downloadCount := downloadCounts[relativeFilePath]
			filePath := filepath.Join(currentPath, fileName)
			// 文件，提供下载和分享链接，并添加删除链接
			shareID, shared := findShareIDByPath(filePath)
			// fmt.Println(shareID)
			// fmt.Println(shared)
			shareLink := ""
			if shared {
				shareLink = fmt.Sprintf(" - <a href='http://%s/shared/%s'>Shared Link</a>", r.Host, shareID)
			}
			if isMediaFile(fileName) {
				mediaPlayerButton := generateMediaPlayer(relativeFilePath, "player"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download?file=%s'>Download</a> - (Download count: %d) - <a href='/share?file=%s'>Share</a>%s - <a href='#' onclick=\"confirmDelete('%s')\">Delete - <a href='#' onclick=\"promptRename('%s')\">Rename</a> - <form action='/move' method='post'><input type='hidden' name='source' value='%s'><input type='text' name='target' placeholder='Enter target path'><input type='submit' value='Move'></form> - </a> - <a href='%s'>Direct Link</a> - %s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), downloadCount, url.QueryEscape(relativeFilePath), shareLink, deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), directLink, mediaPlayerButton)
			} else if isJPEGFile(fileName) {
				imagePreviewButton := generateImagePreview(relativeFilePath, "preview"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download?file=%s'>Download</a> - (Download count: %d) - <a href='/share?file=%s'>Share</a>%s - <a href='#' onclick=\"confirmDelete('%s')\">Delete - <a href='#' onclick=\"promptRename('%s')\">Rename</a> - <form action='/move' method='post'><input type='hidden' name='source' value='%s'><input type='text' name='target' placeholder='Enter target path'><input type='submit' value='Move'></form> - </a> - <a href='%s'>Direct Link</a> - %s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), downloadCount, url.QueryEscape(relativeFilePath), shareLink, deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), directLink, imagePreviewButton)
			} else if isTextFile(fileName) {
				textPreviewButton := generateTextPreview(relativeFilePath, "text"+strconv.Itoa(i))
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download?file=%s'>Download</a> - (Download count: %d) - <a href='/share?file=%s'>Share</a>%s - <a href='#' onclick=\"confirmDelete('%s')\">Delete</a> - <a href='#' onclick=\"promptRename('%s')\">Rename</a> - <form action='/move' method='post'><input type='hidden' name='source' value='%s'><input type='text' name='target' placeholder='Enter target path'><input type='submit' value='Move'></form> - <a href='%s'>Direct Link</a> - %s</p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), downloadCount, url.QueryEscape(relativeFilePath), shareLink, deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), directLink, textPreviewButton)
			} else {
				fmt.Fprintf(w, "<p>%s (size: %s) - (Last modified: %s) - <a href='/download?file=%s'>Download</a> - (Download count: %d) - <a href='/share?file=%s'>Share</a>%s - <a href='#' onclick=\"confirmDelete('%s')\">Delete - <a href='#' onclick=\"promptRename('%s')\">Rename</a> - <form action='/move' method='post'><input type='hidden' name='source' value='%s'><input type='text' name='target' placeholder='Enter target path'><input type='submit' value='Move'></form> - </a> - <a href='%s'>Direct Link</a> - </p>", fileName, fileSize, modTime, url.QueryEscape(relativeFilePath), downloadCount, url.QueryEscape(relativeFilePath), shareLink, deletePath, url.QueryEscape(relativeFilePath), url.QueryEscape(relativeFilePath), directLink)
			}
		}
	}

	fmt.Fprintf(w, `
	<script>
function confirmDelete(itemPath) {
	if (confirm("Are you sure you want to delete this item?")) {
		// 如果用户确认删除，则发送POST请求到/delete路由
		var form = document.createElement('form');
		form.method = 'POST';
		form.action = '/delete';
	
		// 创建隐藏的输入元素，包含要删除的项的路径
		var hiddenField = document.createElement('input');
		hiddenField.type = 'hidden';
		hiddenField.name = 'item';
		hiddenField.value = itemPath;
		form.appendChild(hiddenField);
	
		// 必须将表单添加到文档中才能提交
		document.body.appendChild(form);
		form.submit();
	}
}
function createAudioPlayer(filePath, id) {
    var playerElement = document.getElementById(id);
    if (playerElement.innerHTML !== '') {
        // 如果已经创建了播放器，那么停止播放并隐藏
        playerElement.innerHTML = '';
    } else {
        // 否则，创建新的播放器
        playerElement.innerHTML = '<audio controls preload="auto" style="max-width: 80vw; max-height: 500px;"><source src="/download?file=' + filePath + '" type="audio/mpeg">Your browser does not support the audio element.</audio>';
    }
}

function createVideoPlayer(filePath, id) {
    var playerElement = document.getElementById(id);
    if (playerElement.innerHTML !== '') {
        // 如果已经创建了播放器，那么停止播放并隐藏
        playerElement.innerHTML = '';
    } else {
        // 否则，创建新的播放器
        playerElement.innerHTML = '<video controls preload="auto" style="max-width: 80vw; max-height: 500px;"><source src="/download?file=' + filePath + '" type="video/mp4">Your browser does not support the video element.</video>';
    }
}

function createImagePreview(filePath, id) {
    var previewElement = document.getElementById(id);
    if (previewElement.innerHTML !== '') {
        // 如果已经创建了预览，那么清除预览
        previewElement.innerHTML = '';
    } else {
        // 否则，创建新的预览
        // 添加了style属性，设定了最大宽度和最大高度，图片会自动缩放以适应这个尺寸，同时保持其原始的长宽比
        previewElement.innerHTML = '<img src="/download?file=' + filePath + '" alt="Image preview" style="max-width: 500px; max-height: 500px;">';
    }
}

function createTextPreview(filePath, id) {
    var previewElement = document.getElementById(id);
    if (previewElement.innerHTML !== '') {
        // 如果已经创建了预览，那么清除预览
        previewElement.innerHTML = '';
    } else {
        // 否则，发送请求获取文件内容
        fetch('/download?file=' + filePath + '&timestamp=' + Date.now())
            .then(response => response.text())
            .then(data => {
                // 创建一个textarea元素，用户可以在这个元素中预览和编辑文件内容
                // 增加了一个保存按钮
                previewElement.innerHTML = '<textarea id="textarea' + id + '" style="width: 80vw; height: 500px;">' + data + '</textarea><button onclick="saveText(\'' + filePath + '\', \'' + id + '\')">Save</button>';
				// 打印文件内容和路径到控制台
				// console.log('文件路径：' + filePath);
				// console.log('文件内容：' + data);
				});
    }
}

function saveText(filePath, id) {
    var textarea = document.getElementById('textarea' + id);
    var content = textarea.value;

    // 创建一个新的FormData对象
    var formData = new FormData();
    formData.append('file', filePath);
    formData.append('content', content);

    // 发送POST请求到服务器
    fetch('/save', {
        method: 'POST',
        body: formData
    }).then(response => {
        if (response.ok) {
            alert('Save successful!');
        } else {
            alert('Save failed!');
        }
    });
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

</script>	
`)

	// 添加返回上一级文件夹的链接
	if currentPath != "" {
		parentPath := filepath.Dir(currentPath)
		if parentPath == "." || parentPath == "/" {
			parentPath = ""
		}
		fmt.Fprintf(w, "<a href='/files?path=%s'>Back</a><br>", url.QueryEscape(parentPath))
	}
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
