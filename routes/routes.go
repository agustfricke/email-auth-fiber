package routes

import (
	"github.com/agustfricke/super-auth-go/handlers"
	"github.com/agustfricke/super-auth-go/middleware"
	"github.com/gofiber/fiber/v2"
)

func Routes(app *fiber.App) {
	app.Post("/signin", handlers.SignIn)
	app.Post("/signup", handlers.SignUp)
	app.Get("/verify/:token", handlers.VerifyEmail)
	app.Get("/me", middleware.DeserializeUser, handlers.GetMe)
	app.Get("/logout", middleware.DeserializeUser, handlers.Logout)
}


