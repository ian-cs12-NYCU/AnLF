package sbi

import (
"github.com/gin-gonic/gin"
"net/http"
)

type Route struct {
Method  string
Pattern string
APIFunc gin.HandlerFunc
}

func applyRoutes(group *gin.RouterGroup, routes []Route) {
for _, route := range routes {
switch route.Method {
case http.MethodGet:
group.GET(route.Pattern, route.APIFunc)
case http.MethodPost:
group.POST(route.Pattern, route.APIFunc)
case http.MethodPut:
group.PUT(route.Pattern, route.APIFunc)
case http.MethodDelete:
group.DELETE(route.Pattern, route.APIFunc)
case http.MethodPatch:
group.PATCH(route.Pattern, route.APIFunc)
}
}
}

func (s *Server) getAnalyticsInfoRoutes() []Route {
return []Route{
{
Method:  http.MethodGet,
Pattern: "/analytics",
APIFunc: s.handleGetAnalytics,
},
}
}

func (s *Server) getEventSubscriptionRoutes() []Route {
return []Route{
{
Method:  http.MethodPost,
Pattern: "/subscriptions",
APIFunc: s.handleCreateSubscription,
},
}
}

func (s *Server) handleGetAnalytics(c *gin.Context) {
c.JSON(http.StatusOK, gin.H{"message": "ANLF Analytics Info"})
}

func (s *Server) handleCreateSubscription(c *gin.Context) {
c.JSON(http.StatusCreated, gin.H{"message": "Subscription created"})
}
