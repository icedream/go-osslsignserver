package gin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	requestSigningSecret      []byte
	timestampSkewSecs         int
	requestSigningSecretMutex sync.RWMutex
)

// ErrEmptySecret is returned when the signing secret file is empty.
var ErrEmptySecret = errors.New("signing secret file is empty")

// SetRequestSigningSecret loads the HMAC secret from a file.
func SetRequestSigningSecret(secretPath string) error {
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return ErrEmptySecret
	}
	requestSigningSecretMutex.Lock()
	defer requestSigningSecretMutex.Unlock()
	requestSigningSecret = data
	return nil
}

// SetTimestampSkew sets the acceptable timestamp skew in seconds.
func SetTimestampSkew(skewSecs int) {
	requestSigningSecretMutex.Lock()
	defer requestSigningSecretMutex.Unlock()
	timestampSkewSecs = skewSecs
}

// constantTimeCompare performs a constant-time byte comparison.
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}

// RequestSigningMiddleware validates request signatures using HMAC-SHA256.
// Expected headers:
//   - X-Timestamp: ISO 8601 timestamp (e.g., 2026-05-15T00:00:00Z)
//   - X-Request-ID: Unique request identifier
//   - X-Request-Signature: HMAC-SHA256 signature of canonical request
//
// Canonical request format:
//
//	POST\n
//	/v1/sign\n
//	<timestamp>\n
//	<request-id>\n
//	<file-sha256-hex>\n
//	<profile>\n
func RequestSigningMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract headers
		timestamp := c.GetHeader("X-Timestamp")
		requestID := c.GetHeader("X-Request-ID")
		signature := c.GetHeader("X-Request-Signature")

		// Validate headers are present
		if timestamp == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "X-Timestamp header required",
			})
			c.Abort()
			return
		}
		if requestID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "X-Request-ID header required",
			})
			c.Abort()
			return
		}
		if signature == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "X-Request-Signature header required",
			})
			c.Abort()
			return
		}

		// Validate timestamp freshness
		if err := validateTimestamp(timestamp); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("timestamp validation failed: %v", err),
			})
			c.Abort()
			return
		}

		// Parse multipart form to get file and profile
		if err := c.Request.ParseMultipartForm(64 << 20); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "failed to parse form: " + err.Error(),
			})
			c.Abort()
			return
		}

		// Get file from form
		fileHeader := c.Request.MultipartForm.File["file"]
		if len(fileHeader) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "file is required",
			})
			c.Abort()
			return
		}

		file, err := fileHeader[0].Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "failed to open file: " + err.Error(),
			})
			c.Abort()
			return
		}
		defer func() { _ = file.Close() }()

		// Compute file SHA256
		fileHash := sha256.New()
		if _, err := io.Copy(fileHash, file); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to compute file hash: " + err.Error(),
			})
			c.Abort()
			return
		}
		fileSHA256 := hex.EncodeToString(fileHash.Sum(nil))

		// Get profile from form
		profileValues := c.Request.MultipartForm.Value["profile"]
		if len(profileValues) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "profile is required",
			})
			c.Abort()
			return
		}
		profile := profileValues[0]

		// Construct canonical request
		canonical := strings.Join([]string{
			"POST",
			"/v1/sign",
			timestamp,
			requestID,
			fileSHA256,
			profile,
			"",
		}, "\n")

		// Compute expected signature
		requestSigningSecretMutex.RLock()
		defer requestSigningSecretMutex.RUnlock()

		mac := hmac.New(sha256.New, requestSigningSecret)
		mac.Write([]byte(canonical))
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		// Compare signatures using constant-time comparison
		if !constantTimeCompare([]byte(signature), []byte(expectedSignature)) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "invalid request signature",
			})
			c.Abort()
			return
		}

		// Signature is valid - proceed
		c.Next()
	}
}

// validateTimestamp checks if timestamp is within acceptable skew.
func validateTimestamp(timestamp string) error {
	parsedTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}

	now := time.Now().UTC()
	skew := time.Duration(timestampSkewSecs) * time.Second

	if parsedTime.Before(now.Add(-skew)) {
		return errors.New("timestamp is too old")
	}
	if parsedTime.After(now.Add(skew)) {
		return errors.New("timestamp is in the future")
	}

	return nil
}
