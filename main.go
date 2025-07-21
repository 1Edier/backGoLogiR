package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	
	"time"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Estructuras de datos
type User struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email            string             `bson:"email" json:"email"`
	Password         string             `bson:"password" json:"-"` // No se serializa en JSON
	IsVerified       bool               `bson:"is_verified" json:"is_verified"`
	VerificationCode string             `bson:"verification_code" json:"-"`
	CodeExpiry       time.Time          `bson:"code_expiry" json:"-"`
	CreatedAt        time.Time          `bson:"created_at" json:"created_at"`
}

type LoginRequest struct {
	Email            string `json:"email" validate:"required,email"`
	Password         string `json:"password" validate:"required"`
	VerificationCode string `json:"verification_code,omitempty"`
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type VerifyCodeRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Variables globales
var (
	db     *mongo.Database
	client *mongo.Client
)

// Configuración de email
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	EmailAddress string
	EmailPassword string
}

var emailConfig EmailConfig

func main() {
	// Cargar variables de entorno desde .env
	if err := godotenv.Load(); err != nil {
		log.Println("No se encontró archivo .env, usando variables de entorno del sistema")
	}

	// Inicializar configuración de email
	emailConfig = EmailConfig{
		SMTPHost:      "smtp.gmail.com",
		SMTPPort:      "587",
		EmailAddress:  os.Getenv("EMAIL_ADDRESS"),
		EmailPassword: os.Getenv("EMAIL_PASSWORD"),
	}

	// Verificar que las variables de entorno están configuradas
	if emailConfig.EmailAddress == "" {
		log.Fatal("EMAIL_ADDRESS no está configurado en las variables de entorno")
	}
	if emailConfig.EmailPassword == "" {
		log.Fatal("EMAIL_PASSWORD no está configurado en las variables de entorno")
	}

	log.Printf("Email configurado para: %s", emailConfig.EmailAddress)

	// Conectar a MongoDB
	if err := connectDB(); err != nil {
		log.Fatal("Error conectando a MongoDB:", err)
	}
	defer client.Disconnect(context.TODO())

	// Crear instancia de Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000"}, // Puerto del React
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders: []string{"*"},
	}))

	// Rutas
	api := e.Group("/api")
	
	// Rutas de autenticación
	api.POST("/register", registerHandler)
	api.POST("/login", loginHandler)
	api.POST("/verify-code", verifyCodeHandler)
	api.POST("/resend-code", resendCodeHandler)

	// Ruta protegida de ejemplo
	api.GET("/profile", profileHandler, authMiddleware)

	// Iniciar servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "4000"
	}
	log.Printf("Servidor iniciado en puerto %s", port)
	log.Fatal(e.Start(":" + port))
}

// Conectar a MongoDB
func connectDB() error {
	// Reemplaza <db_password> con tu contraseña real
	uri := "mongodb+srv://admin:edier20042004@compiladoresr.6oxafwv.mongodb.net/?retryWrites=true&w=majority&appName=compiladoresR"
	
	clientOptions := options.Client().ApplyURI(uri)
	var err error
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return err
	}

	// Verificar conexión
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return err
	}

	db = client.Database("auth_system")
	log.Println("Conectado exitosamente a MongoDB")
	return nil
}

// Generar código de verificación
func generateVerificationCode() string {
	code := make([]byte, 3)
	rand.Read(code)
	return fmt.Sprintf("%06d", int(code[0])<<16|int(code[1])<<8|int(code[2]))[:6]
}

// Enviar email
func sendVerificationEmail(email, code string) error {
	log.Printf("Intentando enviar email a: %s", email)
	log.Printf("Usando configuración SMTP: %s:%s", emailConfig.SMTPHost, emailConfig.SMTPPort)
	log.Printf("Email desde: %s", emailConfig.EmailAddress)

	if emailConfig.EmailAddress == "" || emailConfig.EmailPassword == "" {
		return fmt.Errorf("configuración de email no encontrada - EMAIL_ADDRESS: '%s', EMAIL_PASSWORD: '%s'", 
			emailConfig.EmailAddress, 
			func() string { if emailConfig.EmailPassword == "" { return "vacío" } else { return "configurado" } }())
	}

	auth := smtp.PlainAuth("", emailConfig.EmailAddress, emailConfig.EmailPassword, emailConfig.SMTPHost)

	subject := "Código de verificación"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>Código de verificación</h2>
			<p>Tu código de verificación es: <strong>%s</strong></p>
			<p>Este código expira en 10 minutos.</p>
		</body>
		</html>
	`, code)

	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s", email, subject, body)

	err := smtp.SendMail(emailConfig.SMTPHost+":"+emailConfig.SMTPPort, auth, emailConfig.EmailAddress, []string{email}, []byte(msg))
	if err != nil {
		log.Printf("Error detallado enviando email: %v", err)
		return err
	}
	
	log.Printf("Email enviado exitosamente a: %s", email)
	return nil
}

// Handler para registro
func registerHandler(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "Datos inválidos",
		})
	}

	log.Printf("Procesando registro para email: %s", req.Email)

	// Verificar si el usuario ya existe
	collection := db.Collection("users")
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		return c.JSON(http.StatusConflict, Response{
			Success: false,
			Message: "El usuario ya existe",
		})
	}

	// Generar código de verificación
	verificationCode := generateVerificationCode()
	codeExpiry := time.Now().Add(10 * time.Minute)

	log.Printf("Código generado: %s para %s", verificationCode, req.Email)

	// Crear nuevo usuario
	newUser := User{
		Email:            req.Email,
		Password:         req.Password, // En producción, hashearlo
		IsVerified:       false,
		VerificationCode: verificationCode,
		CodeExpiry:       codeExpiry,
		CreatedAt:        time.Now(),
	}

	result, err := collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		log.Printf("Error insertando usuario: %v", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "Error creando usuario",
		})
	}

	// Enviar email de verificación
	if err := sendVerificationEmail(req.Email, verificationCode); err != nil {
		log.Printf("Error enviando email: %v", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "Usuario creado pero error enviando email de verificación",
		})
	}

	return c.JSON(http.StatusCreated, Response{
		Success: true,
		Message: "Usuario registrado. Revisa tu email para el código de verificación",
		Data:    bson.M{"user_id": result.InsertedID},
	})
}

// Handler para login
func loginHandler(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "Datos inválidos",
		})
	}

	log.Printf("Procesando login para email: %s", req.Email)

	// Buscar usuario
	collection := db.Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "Credenciales inválidas",
		})
	}

	// Verificar contraseña (en producción, comparar hash)
	if user.Password != req.Password {
		return c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "Credenciales inválidas",
		})
	}

	// Si el usuario no está verificado, generar nuevo código y enviarlo
	if !user.IsVerified {
		verificationCode := generateVerificationCode()
		codeExpiry := time.Now().Add(10 * time.Minute)

		log.Printf("Usuario no verificado, generando nuevo código: %s", verificationCode)

		// Actualizar código en base de datos
		update := bson.M{
			"$set": bson.M{
				"verification_code": verificationCode,
				"code_expiry":       codeExpiry,
			},
		}
		collection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)

		// Enviar código por email
		if err := sendVerificationEmail(req.Email, verificationCode); err != nil {
			log.Printf("Error enviando email: %v", err)
		}

		return c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "Cuenta no verificada. Se ha enviado un código de verificación a tu email",
		})
	}

	// Si se proporciona código de verificación, validarlo
	if req.VerificationCode != "" {
		if user.VerificationCode != req.VerificationCode || time.Now().After(user.CodeExpiry) {
			return c.JSON(http.StatusUnauthorized, Response{
				Success: false,
				Message: "Código de verificación inválido o expirado",
			})
		}
	}

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "Login exitoso",
		Data: bson.M{
			"user": bson.M{
				"id":    user.ID,
				"email": user.Email,
			},
		},
	})
}

// Handler para verificar código
func verifyCodeHandler(c echo.Context) error {
	var req VerifyCodeRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "Datos inválidos",
		})
	}

	// Buscar usuario
	collection := db.Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		return c.JSON(http.StatusNotFound, Response{
			Success: false,
			Message: "Usuario no encontrado",
		})
	}

	// Verificar código y expiración
	if user.VerificationCode != req.Code {
		return c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "Código de verificación inválido",
		})
	}

	if time.Now().After(user.CodeExpiry) {
		return c.JSON(http.StatusUnauthorized, Response{
			Success: false,
			Message: "Código de verificación expirado",
		})
	}

	// Marcar usuario como verificado
	update := bson.M{
		"$set": bson.M{
			"is_verified":       true,
			"verification_code": "",
		},
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "Error actualizando usuario",
		})
	}

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "Código verificado exitosamente",
	})
}

// Handler para reenviar código
func resendCodeHandler(c echo.Context) error {
	var req struct {
		Email string `json:"email" validate:"required,email"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "Datos inválidos",
		})
	}

	// Buscar usuario
	collection := db.Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": req.Email}).Decode(&user)
	if err != nil {
		return c.JSON(http.StatusNotFound, Response{
			Success: false,
			Message: "Usuario no encontrado",
		})
	}

	if user.IsVerified {
		return c.JSON(http.StatusBadRequest, Response{
			Success: false,
			Message: "Usuario ya verificado",
		})
	}

	// Generar nuevo código
	verificationCode := generateVerificationCode()
	codeExpiry := time.Now().Add(10 * time.Minute)

	// Actualizar en base de datos
	update := bson.M{
		"$set": bson.M{
			"verification_code": verificationCode,
			"code_expiry":       codeExpiry,
		},
	}
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "Error actualizando código",
		})
	}

	// Enviar email
	if err := sendVerificationEmail(req.Email, verificationCode); err != nil {
		log.Printf("Error enviando email: %v", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Success: false,
			Message: "Error enviando email",
		})
	}

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "Código reenviado exitosamente",
	})
}

// Handler para perfil (ruta protegida de ejemplo)
func profileHandler(c echo.Context) error {
	userEmail := c.Get("user_email").(string)
	
	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "Perfil obtenido exitosamente",
		Data: bson.M{
			"email": userEmail,
		},
	})
}

// Middleware de autenticación básico
func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Aquí implementarías la validación de JWT o sesión
		// Por simplicidad, solo verificamos el header de email
		email := c.Request().Header.Get("X-User-Email")
		if email == "" {
			return c.JSON(http.StatusUnauthorized, Response{
				Success: false,
				Message: "No autorizado",
			})
		}

		// Verificar que el usuario existe y está verificado
		collection := db.Collection("users")
		var user User
		err := collection.FindOne(context.TODO(), bson.M{
			"email":       email,
			"is_verified": true,
		}).Decode(&user)
		
		if err != nil {
			return c.JSON(http.StatusUnauthorized, Response{
				Success: false,
				Message: "Usuario no autorizado",
			})
		}

		c.Set("user_email", email)
		return next(c)
	}
}