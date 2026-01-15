# 🔐 Backend de Autenticación

API RESTful con autenticación JWT usando Express.js y bcrypt.

## 🚀 Instalación

```bash
cd backend
npm install
```

## ▶️ Ejecutar

```bash
# Modo desarrollo (con nodemon)
npm run dev

# Modo producción
npm start
```

El servidor se ejecutará en `http://localhost:3000`

## 📡 Endpoints

### Registro de usuario
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123",
  "name": "Usuario Test"
}
```

**Respuesta exitosa (201)**:
```json
{
  "message": "Usuario registrado exitosamente",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "usuario@example.com",
    "name": "Usuario Test",
    "role": "user",
    "createdAt": "2024-01-07T..."
  }
}
```

### Inicio de sesión
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "usuario@example.com",
  "password": "password123"
}
```

**Respuesta exitosa (200)**:
```json
{
  "message": "Login exitoso",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "usuario@example.com",
    "name": "Usuario Test",
    "role": "user"
  }
}
```

### Obtener perfil (requiere autenticación)
```http
GET /api/auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Respuesta exitosa (200)**:
```json
{
  "id": 1,
  "email": "usuario@example.com",
  "name": "Usuario Test",
  "role": "user",
  "createdAt": "2024-01-07T..."
}
```

### Ruta protegida de ejemplo
```http
GET /api/protected
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Respuesta exitosa (200)**:
```json
{
  "message": "🎉 Acceso concedido a contenido protegido",
  "user": {
    "userId": 1,
    "email": "usuario@example.com",
    "role": "user"
  },
  "timestamp": "2024-01-07T..."
}
```

## 🔑 Variables de entorno

Crea un archivo `.env` en la raíz del backend:

```env
JWT_SECRET=tu-secreto-super-seguro-cambialo
PORT=3000
```

## 🧪 Probar con curl

### Registro
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123","name":"Test User"}'
```

### Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'
```

### Perfil (reemplaza TOKEN con el token obtenido)
```bash
curl http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer TOKEN"
```

## 📝 Notas

- Los usuarios se almacenan en memoria (se pierden al reiniciar el servidor)
- En producción, usar una base de datos real (MongoDB, PostgreSQL, etc.)
- El JWT expira en 24 horas
- Las contraseñas se hashean con bcrypt (10 salt rounds)

## 🛡️ Seguridad

- ✅ Contraseñas hasheadas con bcrypt
- ✅ Tokens JWT con expiración
- ✅ Validación de datos de entrada
- ✅ CORS habilitado
- ✅ No se exponen contraseñas en respuestas

## 📚 Tecnologías

- **Express.js**: Framework web
- **jsonwebtoken**: Generación y verificación de JWT
- **bcryptjs**: Hash de contraseñas
- **cors**: Manejo de CORS
- **dotenv**: Variables de entorno
