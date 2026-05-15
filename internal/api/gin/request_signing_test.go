package gin

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	ginlib "github.com/gin-gonic/gin"
	"github.com/icedream/go-osslsignserver/internal/api/gin/server"
)

func setupRequestSigningTest(t *testing.T) (string, string) {
	// Create temporary secret file
	secretFile := "/tmp/test-request-signing-secret.txt"
	secretKey := "my-super-secret-key-for-testing"
	err := os.WriteFile(secretFile, []byte(secretKey), 0o400)
	if err != nil {
		t.Fatalf("Failed to create secret file: %v", err)
	}

	// Load secret
	err = SetRequestSigningSecret(secretFile)
	if err != nil {
		t.Fatalf("Failed to set request signing secret: %v", err)
	}

	// Set timestamp skew to 5 minutes
	SetTimestampSkew(300)

	return secretFile, secretKey
}

func createSignedRequest(t *testing.T, secretKey string, fileContent []byte, profile string) (*http.Request, string) {
	// Compute file SHA256
	fileHash := sha256.Sum256(fileContent)
	fileSHA256 := hex.EncodeToString(fileHash[:])

	// Create timestamp and request ID
	timestamp := time.Now().UTC().Format(time.RFC3339)
	requestID := "test-request-id-12345"

	// Create canonical request
	canonical := fmt.Sprintf("POST\n/v1/sign\n%s\n%s\n%s\n%s\n",
		timestamp, requestID, fileSHA256, profile)

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Create multipart request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add profile field
	writer.WriteField("profile", profile)

	// Add file
	part, err := writer.CreateFormFile("file", "test.bin")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, err = io.Copy(part, bytes.NewReader(fileContent))
	if err != nil {
		t.Fatalf("Failed to write file content: %v", err)
	}

	writer.Close()

	// Create HTTP request
	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("X-Request-Signature", signature)

	return req, signature
}

func TestRequestSigningMiddleware_ValidSignature(t *testing.T) {
	secretFile, secretKey := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	profile := "testprofile"

	req, _ := createSignedRequest(t, secretKey, fileContent, profile)

	// Create router with middleware
	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "signed successfully"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRequestSigningMiddleware_MissingTimestamp(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Request-ID", "test-id")
	req.Header.Set("X-Request-Signature", "somesig")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_MissingRequestID(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Request-Signature", "somesig")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_MissingSignature(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Request-ID", "test-id")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_InvalidSignature(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Request-ID", "test-id")
	req.Header.Set("X-Request-Signature", "invalid-signature")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_TamperedFile(t *testing.T) {
	secretFile, secretKey := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	// Create signature with one file content
	originalContent := []byte("original binary content")
	_, signature := createSignedRequest(t, secretKey, originalContent, "testprofile")

	// But send different file content
	tamperedContent := []byte("tampered binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(tamperedContent))
	writer.Close()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	requestID := "test-request-id-12345"

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("X-Request-Signature", signature)

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for tampered file, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_OldTimestamp(t *testing.T) {
	secretFile, secretKey := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	profile := "testprofile"

	// Create signature with old timestamp (10 minutes ago)
	fileHash := sha256.Sum256(fileContent)
	fileSHA256 := hex.EncodeToString(fileHash[:])
	oldTimestamp := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	requestID := "test-request-id-12345"

	canonical := fmt.Sprintf("POST\n/v1/sign\n%s\n%s\n%s\n%s\n",
		oldTimestamp, requestID, fileSHA256, profile)

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(canonical))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Create request with old timestamp
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", profile)
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", oldTimestamp)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("X-Request-Signature", signature)

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for old timestamp, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_MissingFile(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	// Create request without file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("profile", "testprofile")
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Request-ID", "test-id")
	req.Header.Set("X-Request-Signature", "somesig")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for missing file, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_MissingProfile(t *testing.T) {
	secretFile, _ := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	fileContent := []byte("test binary content")
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.bin")
	io.Copy(part, bytes.NewReader(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/v1/sign", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Request-ID", "test-id")
	req.Header.Set("X-Request-Signature", "somesig")

	router := ginlib.Default()
	router.POST("/v1/sign", RequestSigningMiddleware(), func(c *ginlib.Context) {
		c.JSON(http.StatusOK, map[string]interface{}{"message": "ok"})
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for missing profile, got %d", w.Code)
	}
}

func TestRequestSigningMiddleware_WithServerRouter(t *testing.T) {
	secretFile, secretKey := setupRequestSigningTest(t)
	defer os.Remove(secretFile)

	// Create router using server.NewRouter with middleware
	router := server.NewRouter(
		server.RouteGroup{
			Prefix: "/v1",
			Middleware: []ginlib.HandlerFunc{
				RequestSigningMiddleware(),
			},
			Routes: server.Routes{
				{
					"Sign",
					"POST",
					"/sign",
					server.Sign,
				},
			},
		},
	)

	fileContent := []byte("test binary content")
	req, _ := createSignedRequest(t, secretKey, fileContent, "testprofile")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail because SigningService is nil (500), but not auth (401/403)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("Request should pass auth but got %d: %s", w.Code, w.Body.String())
	}
	if w.Code != http.StatusInternalServerError {
		t.Logf("Got status %d (expected 500 since service not initialized)", w.Code)
	}
}
