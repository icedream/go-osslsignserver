package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
	"log/slog"
)

// Logger returns a Gin middleware that emits request logs through slog.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		attrs := []any{
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"latency", latency,
			"clientIP", c.ClientIP(),
			"userAgent", c.Request.UserAgent(),
			"contentLength", c.Request.ContentLength,
		}
		if rawQuery := c.Request.URL.RawQuery; rawQuery != "" {
			attrs = append(attrs, "query", rawQuery)
		}
		if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
			attrs = append(attrs, "requestID", requestID)
		}
		if len(c.Errors) > 0 {
			attrs = append(attrs, "errors", c.Errors.String())
		}

		if status >= http.StatusInternalServerError {
			slog.Error("gin request", attrs...)
			return
		}
		slog.Info("gin request", attrs...)
	}
}

// Recovery returns a Gin recovery middleware that logs panics through slog.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		stack := debug.Stack()
		sum := sha256.Sum256(stack)
		slog.Error("gin panic recovered",
			"panic", recovered,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"clientIP", c.ClientIP(),
			"stackHash", hex.EncodeToString(sum[:]),
			"stack", string(stack),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}
