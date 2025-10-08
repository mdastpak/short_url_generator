package handler

import (
	_ "embed"
	"net/http"

	"github.com/rs/zerolog/log"
)

//go:embed admin_dashboard.html
var adminDashboardHTML []byte

// ServeDashboard handles GET /admin/dashboard
// @Summary Serve admin dashboard UI
// @Description Returns the admin dashboard HTML interface
// @Tags Admin
// @Produce html
// @Success 200 {string} html "Admin dashboard HTML"
// @Router /admin/dashboard [get]
func (h *URLHandler) ServeDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	w.Write(adminDashboardHTML)

	log.Info().
		Str("ip", r.RemoteAddr).
		Msg("Admin dashboard accessed")
}
