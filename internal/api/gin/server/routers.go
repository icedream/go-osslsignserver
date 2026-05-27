package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	apiginglog "github.com/icedream/go-osslsignserver/internal/api/gin/logging"
	"github.com/icedream/go-osslsignserver/internal/signing"
)

// Service holds reference to the signing service.
var Service *signing.Service

// SetService sets the signing service for handlers to use.
func SetService(s *signing.Service) {
	Service = s
}

// Route is the information for every URI.
type Route struct {
	// Name is the name of this Route.
	Name string
	// Method is the string for the HTTP method. ex) GET, POST etc..
	Method string
	// Pattern is the pattern of the URI.
	Pattern string
	// HandlerFunc is the handler function of this route.
	HandlerFunc gin.HandlerFunc
}

// Routes is the list of the generated Route.
type Routes []Route

// RouteGroup defines a group of routes that share the same middleware.
type RouteGroup struct {
	// Prefix is the route group prefix (e.g., "/v1/")
	Prefix string
	// Middleware is a list of middleware to apply to all routes in the group
	Middleware []gin.HandlerFunc
	// Routes is the list of routes in the group
	Routes Routes
}

// NewRouter returns a new router with middleware applied.
func NewRouter(routeGroups ...RouteGroup) *gin.Engine {
	router := gin.New()
	router.Use(apiginglog.Logger())
	router.Use(apiginglog.Recovery())

	// If no route groups provided, use default routes without middleware (legacy behavior)
	if len(routeGroups) == 0 {
		for _, route := range routes {
			switch route.Method {
			case http.MethodGet:
				router.GET(route.Pattern, route.HandlerFunc)
			case http.MethodPost:
				router.POST(route.Pattern, route.HandlerFunc)
			case http.MethodPut:
				router.PUT(route.Pattern, route.HandlerFunc)
			case http.MethodPatch:
				router.PATCH(route.Pattern, route.HandlerFunc)
			case http.MethodDelete:
				router.DELETE(route.Pattern, route.HandlerFunc)
			}
		}
		return router
	}

	// Register routes with middleware from groups
	for _, group := range routeGroups {
		g := router.Group(group.Prefix, group.Middleware...)
		for _, route := range group.Routes {
			switch route.Method {
			case http.MethodGet:
				g.GET(route.Pattern, route.HandlerFunc)
			case http.MethodPost:
				g.POST(route.Pattern, route.HandlerFunc)
			case http.MethodPut:
				g.PUT(route.Pattern, route.HandlerFunc)
			case http.MethodPatch:
				g.PATCH(route.Pattern, route.HandlerFunc)
			case http.MethodDelete:
				g.DELETE(route.Pattern, route.HandlerFunc)
			}
		}
	}

	return router
}

// Index is the index handler.
func Index(c *gin.Context) {
	c.String(http.StatusOK, "Hello World!")
}

// Sign handles multipart/form-data file signing requests.
// Note: Request signature validation happens in RequestSigningMiddleware before this handler.
func Sign(c *gin.Context) {
	if Service == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "signing service not initialized",
		})
		return
	}

	// Get file from already-parsed form (parsed by middleware for signature validation)
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "file is required",
		})
		return
	}
	defer func() { _ = file.Close() }()

	// Get profile ID
	profileID := c.PostForm("profile")
	if profileID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "profile is required",
		})
		return
	}

	// Get optional parameters
	hash := c.PostForm("hash")
	description := c.PostForm("description")
	descriptionURL := c.PostForm("description_url")

	var hashPtr *string
	if hash != "" {
		hashPtr = &hash
	}
	var descriptionPtr *string
	if description != "" {
		descriptionPtr = &description
	}
	var descriptionURLPtr *string
	if descriptionURL != "" {
		descriptionURLPtr = &descriptionURL
	}

	// Perform signing with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	signedData, err := Service.Sign(
		ctx,
		profileID,
		file,
		header.Size,
		hashPtr,
		descriptionPtr,
		descriptionURLPtr,
	)
	switch {
	case err == signing.ErrProfileNotFound:
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	case err == signing.ErrConcurrentLimitReached:
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": err.Error(),
		})
		return
	case err == signing.ErrTokenUnavailable:
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": err.Error(),
		})
		return
	case err == signing.ErrSigningTimeout:
		c.JSON(http.StatusGatewayTimeout, gin.H{
			"error": err.Error(),
		})
		return
	case err == signing.ErrSigningFailed:
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error": err.Error(),
		})
		return
	case err != nil:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Send the signed file back
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename=signed-"+header.Filename)
	c.Data(http.StatusOK, "application/octet-stream", signedData)
}

var routes = Routes{
	{
		"Index",
		http.MethodGet,
		"/",
		Index,
	},

	{
		"Sign",
		http.MethodPost,
		"/sign",
		Sign,
	},
}
