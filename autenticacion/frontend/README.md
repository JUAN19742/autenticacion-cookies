# 🔐 Frontend de Autenticación

Aplicación React con autenticación completa usando JWT y Context API.

## 🚀 Instalación

```bash
cd frontend
npm install
```

## ▶️ Ejecutar

```bash
npm run dev
```

La aplicación se ejecutará en `http://localhost:5173`

## 📋 Requisitos previos

Asegúrate de que el backend esté ejecutándose en `http://localhost:3000`

```bash
cd ../backend
npm run dev
```

## 🏗️ Estructura del proyecto

```
src/
├── App.jsx                 # Componente principal con rutas
├── App.css                 # Estilos globales
├── main.jsx               # Punto de entrada
├── context/
│   └── AuthContext.jsx    # Context API para autenticación
├── services/
│   └── authService.js     # Servicios de API
└── components/
    ├── Navbar.jsx         # Barra de navegación
    ├── Login.jsx          # Página de login
    ├── Register.jsx       # Página de registro
    ├── Dashboard.jsx      # Dashboard protegido
    ├── Home.jsx           # Página de inicio
    └── PrivateRoute.jsx   # Componente para rutas protegidas
```

## 🎯 Características

### Autenticación
- ✅ Registro de usuarios
- ✅ Inicio de sesión
- ✅ Cierre de sesión
- ✅ Persistencia de sesión con localStorage
- ✅ Gestión de estado global con Context API

### Rutas
- `/` - Página de inicio
- `/login` - Iniciar sesión
- `/register` - Crear cuenta
- `/dashboard` - Dashboard protegido (requiere autenticación)

### Seguridad
- ✅ Rutas protegidas con `PrivateRoute`
- ✅ Tokens JWT en headers de peticiones
- ✅ Validación de formularios
- ✅ Manejo de errores
- ✅ Redirección automática al expirar sesión

## 🔧 Configuración

### API URL

Modifica la URL del backend en [src/services/authService.js](src/services/authService.js):

```js
const API_URL = 'http://localhost:3000/api/auth';
```

## 💻 Uso

### 1. Registrar un nuevo usuario

1. Navega a `/register`
2. Completa el formulario:
   - Nombre completo
   - Email
   - Contraseña (mínimo 6 caracteres)
   - Confirmar contraseña
3. Haz clic en "Registrarse"
4. Serás redirigido automáticamente al dashboard

### 2. Iniciar sesión

1. Navega a `/login`
2. Ingresa tu email y contraseña
3. Haz clic en "Iniciar Sesión"
4. Serás redirigido al dashboard

### 3. Acceder al dashboard

- Solo disponible para usuarios autenticados
- Muestra información del usuario
- Contenido protegido

### 4. Cerrar sesión

- Haz clic en "Cerrar Sesión" en la barra de navegación
- Serás redirigido a la página de login

## 🎨 Personalización

### Colores

Modifica las variables CSS en [src/App.css](src/App.css):

```css
:root {
  --primary-color: #4f46e5;
  --secondary-color: #06b6d4;
  --success-color: #10b981;
  --danger-color: #ef4444;
  /* ... más colores */
}
```

### Componentes

Todos los componentes están en `src/components/` y pueden ser modificados según tus necesidades.

## 📦 Dependencias principales

- **React 18**: Biblioteca de UI
- **React Router v6**: Enrutamiento
- **Vite**: Build tool y dev server

## 🐛 Solución de problemas

### Error de conexión con el backend

```
Error: Failed to fetch
```

**Solución**: Verifica que el backend esté ejecutándose en `http://localhost:3000`

### Token expirado

```
Error: Token inválido o expirado
```

**Solución**: Cierra sesión y vuelve a iniciar sesión

### CORS error

```
Access to fetch at 'http://localhost:3000' from origin 'http://localhost:5173' has been blocked by CORS policy
```

**Solución**: Asegúrate de que el backend tenga configurado CORS correctamente

## 📚 Recursos

- [React Documentation](https://react.dev/)
- [React Router](https://reactrouter.com/)
- [Vite](https://vitejs.dev/)

## 🏁 Build para producción

```bash
npm run build
```

Los archivos optimizados se generarán en la carpeta `dist/`

Para previsualizar:

```bash
npm run preview
```
