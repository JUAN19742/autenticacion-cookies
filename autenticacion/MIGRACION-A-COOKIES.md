# Migración de localStorage a Cookies para Autenticación JWT

Esta guía te llevará paso a paso para migrar tu aplicación de autenticación de usar `localStorage` a usar cookies HTTP-only, mejorando significativamente la seguridad.

## ¿Por qué usar Cookies en lugar de localStorage?

### Ventajas de las Cookies HTTP-only:
- 🔒 **Mayor seguridad contra XSS (Cross-site scripting)**: Las cookies con flag `httpOnly` no pueden ser accedidas por JavaScript, protegiéndolas de ataques XSS. Los request pueden seguir haciendo uso de la información almacenada en cookies sin que JavaScript necesite leer.
- 🛡️ **Protección CSRF**: El atributo `sameSite` previene ataques de falsificación de peticiones entre sitios
- 🚫 **Sin exposición del token**: El token JWT nunca es visible en el código JavaScript del cliente

### Desventajas:
- Más complejo de implementar con aplicaciones móviles nativas
- Requiere configuración CORS más cuidadosa
- Posible necesidad de implementar tokens CSRF adicionales

---

## Paso 1: Actualizar el Backend

### 1.1 Instalar cookie-parser

```bash
cd backend
npm install cookie-parser
```

### 1.2 Configurar cookie-parser en server.js

Agrega el middleware de cookies después de los middlewares existentes:

```javascript
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser'); // ← AGREGAR
require('dotenv').config();

const authRoutes = require('./routes/auth');

const app = express();

// Middlewares
app.use(cors({
  origin: 'http://localhost:5173', // ← MODIFICAR: especificar origen
  credentials: true // ← AGREGAR: permitir cookies
}));
app.use(express.json());
app.use(cookieParser()); // ← AGREGAR

// ... resto del código
```

### 1.3 Actualizar las rutas de autenticación (routes/auth.js)

**Modificar el endpoint de registro:**

```javascript
// POST /api/auth/register - Registro de usuario
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // ... código de validación existente ...

    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear nuevo usuario
    const newUser = {
      id: nextId++,
      email,
      password: hashedPassword,
      name,
      role: 'user',
      createdAt: new Date()
    };

    users.push(newUser);

    // Generar token
    const token = jwt.sign(
      { 
        userId: newUser.id, 
        email: newUser.email,
        role: newUser.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // ← AGREGAR: Establecer cookie en lugar de enviar token en el body
    res.cookie('token', token, {
      httpOnly: true,  // No accesible desde JavaScript
      secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
      sameSite: 'strict', // Protección CSRF
      maxAge: 24 * 60 * 60 * 1000 // 24 horas en milisegundos
    });

    // No enviar la contraseña al cliente
    const { password: _, ...userWithoutPassword } = newUser;

    console.log(`✅ Usuario registrado: ${email}`);

    // ← MODIFICAR: No enviar el token en el body
    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: userWithoutPassword
      // Ya NO enviamos 'token' aquí
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});
```

**Modificar el endpoint de login:**

```javascript
// POST /api/auth/login - Inicio de sesión
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // ... código de validación existente ...

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Generar token
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // ← AGREGAR: Establecer cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    });

    const { password: _, ...userWithoutPassword } = user;

    console.log(`✅ Login exitoso: ${email}`);

    // ← MODIFICAR: No enviar el token en el body
    res.json({
      message: 'Inicio de sesión exitoso',
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});
```

**Agregar endpoint de logout:**

```javascript
// POST /api/auth/logout - Cerrar sesión
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  console.log('✅ Sesión cerrada');
  
  res.json({ message: 'Sesión cerrada exitosamente' });
});
```

### 1.4 Actualizar el middleware de autenticación en server.js

```javascript
// Middleware de autenticación
function authenticateToken(req, res, next) {
  // ← MODIFICAR: Leer el token desde las cookies
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const jwt = require('jsonwebtoken');
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    req.user = user;
    next();
  });
}
```

### 1.5 Actualizar endpoint GET /api/auth/me (si existe)

En `routes/auth.js`, busca el endpoint `GET /api/auth/me` y asegúrate de que use el middleware:

```javascript
// GET /api/auth/me - Obtener perfil del usuario autenticado
router.get('/me', authenticateToken, (req, res) => {
  // req.user viene del middleware authenticateToken
  const user = users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado' });
  }

  const { password: _, ...userWithoutPassword } = user;
  res.json({ user: userWithoutPassword });
});
```

**IMPORTANTE**: Necesitas exportar o mover `authenticateToken` a `routes/auth.js` o crear un archivo separado de middlewares.

---

## Paso 2: Actualizar el Frontend

### 2.1 Actualizar authService.js

Reemplaza todo el contenido del archivo con:

```javascript
const API_URL = '/api/auth';

export const authService = {
  // Registrar nuevo usuario
  register: async (email, password, name) => {
    const response = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // ← IMPORTANTE: Enviar cookies
      body: JSON.stringify({ email, password, name })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Error al registrar usuario');
    }

    const data = await response.json();
    // ← Ya NO guardamos nada en localStorage
    return data;
  },

  // Iniciar sesión
  login: async (email, password) => {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // ← IMPORTANTE: Enviar cookies
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Error al iniciar sesión');
    }

    const data = await response.json();
    // ← Ya NO guardamos nada en localStorage
    return data;
  },

  // Cerrar sesión
  logout: async () => {
    try {
      await fetch(`${API_URL}/logout`, {
        method: 'POST',
        credentials: 'include' // ← IMPORTANTE: Enviar cookies
      });
    } catch (error) {
      console.error('Error al cerrar sesión:', error);
    }
  },

  // Obtener perfil del servidor
  getProfile: async () => {
    const response = await fetch(`${API_URL}/me`, {
      credentials: 'include' // ← IMPORTANTE: Enviar cookies
    });

    if (!response.ok) {
      throw new Error('Error al obtener perfil');
    }

    return response.json();
  },

  // Verificar autenticación llamando al servidor
  checkAuth: async () => {
    try {
      const response = await fetch(`${API_URL}/me`, {
        credentials: 'include'
      });
      return response.ok;
    } catch {
      return false;
    }
  }
};
```

### 2.2 Actualizar AuthContext.jsx

```javascript
import { createContext, useContext, useState, useEffect } from 'react';
import { authService } from '../services/authService';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // ← MODIFICAR: Verificar autenticación con el servidor
  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const response = await authService.getProfile();
        setUser(response.user);
      } catch (error) {
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuthentication();
  }, []);

  // Función de login
  const login = async (email, password) => {
    try {
      const data = await authService.login(email, password);
      setUser(data.user);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // Función de registro
  const register = async (email, password, name) => {
    try {
      const data = await authService.register(email, password, name);
      setUser(data.user);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // ← MODIFICAR: Función de logout
  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  // Verificar si está autenticado
  const isAuthenticated = () => {
    return !!user;
  };

  const value = {
    user,
    login,
    register,
    logout,
    isAuthenticated,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

// Hook personalizado para usar el contexto
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth debe usarse dentro de un AuthProvider');
  }
  return context;
};
```

### 2.3 Actualizar componentes que usen logout

Si tienes componentes como `Navbar.jsx` que llamen a `logout`, actualízalos para manejar la función async:

```javascript
const handleLogout = async () => {
  await logout(); // ← Ahora es async
  navigate('/');
};
```

---

## Paso 3: Probar la Aplicación

1. **Reiniciar el backend:**
   ```bash
   cd backend
   npm start
   ```

2. **Reiniciar el frontend:**
   ```bash
   cd frontend
   npm run dev
   ```

3. **Probar el flujo completo:**
   - Registrar un nuevo usuario
   - Cerrar sesión
   - Iniciar sesión con el usuario creado
   - Acceder al dashboard
   - Refrescar la página (debe mantenerse la sesión)
   - Cerrar sesión

4. **Verificar las cookies en DevTools:**
   - Abre las DevTools (F12)
   - Ve a la pestaña "Application" > "Cookies"
   - Deberías ver una cookie llamada `token` con las propiedades:
     - ✓ HttpOnly
     - ✓ SameSite: Strict

---

## Preguntas de Reflexión (EN SUS PROPIAS PALABRAS)

### Conceptuales:

1. **¿Qué vulnerabilidades de seguridad previenen las cookies HTTP-only que localStorage no puede prevenir? Crea una analogia de ejemplo para tu explicación**
Las cookies HttpOnly evitan que JavaScript en la página lea el token. Eso protege contra ataques donde un script malicioso (inyectado por XSS) intenta robar el token y enviarlo fuera.

Analogía:
Imagina que tu token es una llave que guarda acceso a tu casa.

localStorage es como dejar la llave sobre la mesa: cualquiera que entre a la casa (incluso un ladrón que consiga pasar) puede verla y llevársela.

Una cookie HttpOnly es como poner la llave dentro de una caja fuerte dentro de la casa que solo el portero (el servidor) puede abrir con permiso especial — incluso si un ladrón entra y mira, no puede sacar la llave porque no tiene la combinación.

Qué previene exactamente: robo del token por scripts maliciosos (XSS). localStorage no puede evitar que scripts lean su contenido

2. **¿Por qué es importante el atributo `sameSite: 'strict'` en las cookies?** Investiga: ¿Qué es un ataque CSRF (explica con una analogía) y cómo lo previene este atributo?
SameSite: 'strict' evita que el navegador envíe la cookie cuando la petición viene desde otro sitio web. Esto ayuda mucho a bloquear ataques CSRF.

Qué es un ataque CSRF (analogía):
CSRF es como si alguien te hiciera enviar una carta firmada a un banco sin que te des cuenta.

Tú estás conectado a tu banco en otra pestaña.

Un atacante te convence  para que hagas clic en algo en una web maliciosa.

Esa web maliciosa hace que tu navegador envíe una petición al banco usando tus cookies.

El banco cree que la petición viene de ti y realiza la acción (p. ej. transferir dinero).

SameSite: 'strict' impide que esas peticiones iniciadas desde otro sitio incluyan la cookie, por lo que la petición no tendrá la cookie del usuario y el servidor la rechazará. Es como pedir que la carta venga con un sello que solo se puede poner si la escribes desde dentro del banco — si viene desde afuera, no vale.

3. **¿En qué escenarios NO sería recomendable usar cookies para autenticación, explica porque?**
APIs públicas consumidas por terceros: si otras webs necesitan hacer peticiones en nombre del usuario desde su propio dominio, las cookies con SameSite pueden bloquearlas.

Apps puramente cliente (p. ej. apps móviles o algunas SPAs offline): estas apps controlan mejor tokens en memoria o usan otros métodos porque no pasan por el navegador normal.

Servicios que requieren compartir credenciales entre muchos subdominios sin controles estrictos: configurar cookies para varios dominios puede ser complejo y arriesga exposición si no se hace bien.

Si no puedes garantizar HTTPS en producción: las cookies seguras (Secure) requieren HTTPS; sin HTTPS las cookies pueden exponerse en la red.

### Técnicas:

4. **¿Qué pasaría si olvidas agregar `credentials: 'include'` en las peticiones fetch del frontend?** Experimenta: Elimina temporalmente esta línea y describe el comportamiento observado.

Si quitas credentials: 'include' en fetch, el navegador no enviará las cookies al hacer la petición. Eso significa:

El servidor no recibirá la cookie de sesión/JWT.

Normalmente obtendrás un 401 No autorizado

En la práctica: la petición parece hecha por un usuario sin sesión.

Cómo se ve en la práctica:

Llamas fetch('/api/protected') sin credentials.

DevTools -> Network: en la petición no aparece la cookie en la cabecera Cookie.

El servidor responde con error de autenticación.

Si añades credentials: 'include' luego, la cookie aparece y la petición funciona.

5. **¿Por qué necesitamos configurar CORS con `credentials: true` en el backend?** Investiga: ¿Qué política de seguridad del navegador está en juego aquí?

Cuando frontend y backend están en dominios diferentes, el navegador aplica la política CORS. Para que el navegador permita enviar cookies en peticiones cross-origin, el servidor debe indicar que acepta credenciales y el origen del frontend.

Qué política del navegador está en juego: la política CORS (Cross-Origin Resource Sharing).

El servidor debe enviar Access-Control-Allow-Credentials: true y permitir el origen
Si no se configura, el navegador bloquea las cookies por seguridad.

6. **¿Cómo afecta el uso de cookies a la arquitectura si decides separar frontend y backend en dominios diferentes?** Investiga sobre cookies de terceros y las restricciones del navegador.

Si el frontend está en app.example.com y el backend en api.example.com o en otro dominio distinto, las cookies pueden volverse cookies de terceros cuando se envían entre sitios. Los navegadores modernos aplican restricciones fuertes a cookies de terceros (pueden bloquearlas o exigir SameSite=None; Secure).

Consecuencias prácticas:

Necesitas SameSite=None y Secure para que la cookie se envíe en contextos cross-site, pero eso aumenta la exposición y exige HTTPS.

Algunos navegadores o bloqueadores de privacidad podrían bloquear cookies de terceros, rompiendo la autenticación.

Requiere configuración CORS y credentials: include en frontend y Access-Control-Allow-Credentials en backend.

### Casos Prácticos:

7. **Si estas implementando un mecanismo de "recordarme":**
   - ¿Cómo modificarías `maxAge` de la cookie?
   - ¿Qué consideraciones de seguridad debes tener?

Cómo modificar maxAge:

Si quieres que el usuario permanezca "recordado" por ejemplo 30 días, ajustas la cookie: maxAge = 1000 * 60 * 60 * 24 * 30 (milisegundos).

Para "no recordarme" pones duración corta (p. ej. sesión) o expires sólo durante la sesión del navegador.

Consideraciones de seguridad:

Cookies más largas aumentan el riesgo si alguien roba la cookie.

Para mayor seguridad usa refresh tokens con short-lived access tokens: cookie de refresh con HttpOnly y renovación automática.

Ofrece opción de "cerrar todas las sesiones" en la cuenta para invalidar refresh tokens en servidor.

En dispositivos públicos, desaconsejar "recordarme".

8. **Maneja la expiración del token de forma elegante:**
   - ¿Cómo manejarías a nivel de UX (experiencia de usuario) la expiración del token?
   - ¿Cómo redirigirías al login sin perder el contexto de lo que estaba haciendo?

UX al expirar token (simple):

Mostrar un mensaje claro: "Tu sesión expiró. Por favor vuelve a iniciar sesión."

Si la acción está en progreso (por ejemplo completar formulario), ofrece guardar el trabajo localmente (en memoria o en storage temporal) antes de redirigir.

Redirigir sin perder contexto:

Guardar el lugar/acción actual en la URL o en sessionStorage

Después del login, redirigir a returnTo.

Alternativa: abrir modal de login encima de la pantalla actual para que el usuario inicie sesión y luego continúe sin cambiar de página.

### Debugging:

9. **Imagina que recibes el error "Cannot set headers after they are sent to the client":**
    - ¿Qué podría estar causándolo en el contexto de cookies?
    - ¿En qué orden deben ejecutarse `res.cookie()` y `res.json()`?

Qué lo causa:

Ese error aparece si intentas enviar encabezados (como Set-Cookie) después de que ya enviaste la respuesta al cliente (por ejemplo después de res.send() o res.json()).

A veces pasa cuando haces dos respuestas en una ruta por error (ej. un return res.json() y luego en otra rama vuelves a res.cookie() y res.send()).

Orden correcto:

Primero configuras la cookie, p. ej. res.cookie('token', token, opts).
Después envías la respuesta: res.json({ ok: true }) o res.send().
Así te aseguras de que los encabezados (incluyendo Set-Cookie) se puedan agregar antes de enviar el cuerpo.

10. **Las cookies no se están guardando en el navegador:**
    - Lista 3 posibles causas y cómo verificarias cada una (algunas causas podrían tener mas de una solución)
  
Causa 1 — falta credentials: 'include' en fetch/axios

Cómo verificar: en DevTools → Network, revisa la petición; en la cabecera Cookie no aparece la cookie.

Solución: agrega credentials: 'include' en fetch o withCredentials: true en axios.

Causa 2 — SameSite / Secure mal configurado (o navegador bloquea third-party cookies)

Cómo verificar: en DevTools → Application → Cookies no aparece la cookie; revisa Set-Cookie en la respuesta (Network) y mira sus flags. Si SameSite=None debe tener Secure.

Solución: ajustar SameSite y Secure según entorno; usar HTTPS si Secure es requerido; revisar si el navegador bloquea cookies de terceros.

Causa 3 — CORS no permite credenciales (falta Access-Control-Allow-Credentials: true y origen permitido)

Cómo verificar: en la respuesta preflight o respuesta, falta Access-Control-Allow-Credentials o Access-Control-Allow-Origin está en *. Revisa consola del navegador para errores CORS.

Solución: en backend añadir Access-Control-Allow-Credentials: true y Access-Control-Allow-Origin: https://tu-front (no *).

### Arquitectura:

11. **Compara localStorage vs Cookies:**
    - Crea una tabla con al menos 5 criterios de comparación
    - ¿Describe un caso específico en el que usarías cada uno respectivamente y porque?

  ## Comparación: localStorage vs Cookies

### localStorage
- Es accesible desde JavaScript.
- No se envía automáticamente al servidor.
- Tiene más espacio de almacenamiento.
- Es vulnerable a ataques XSS.
- Se debe enviar manualmente en los headers.

### Cookies
- No son accesibles desde JavaScript si usan `HttpOnly`.
- Se envían automáticamente en cada petición.
- Tienen poco espacio de almacenamiento.
- Son más seguras frente a XSS.
- Pueden ser vulnerables a CSRF si no se configuran bien.

### Caso para usar cada uno:

Usar cookies: para autenticación de sesiones en apps web tradicionales donde quieres que el navegador envíe la credencial automáticamente y protegerla con HttpOnly.

Usar localStorage: para datos no sensibles, estados de UI, o cuando controlas manualmente tokens y no interactúas con cookies; por ejemplo guardar preferencias locales que no sean críticos.

12. **Diseña una estrategia de migración (en algún ámbito, stack tecnológico, infraestructura, dominio, etc) para una aplicación en producción:**
    - ¿Cómo harías la transición sin afectar a usuarios activos? Describe con un ejemplo práctico en el ámbito seleccionado
    - ¿Qué pasos de rollback implementarías?

Ejemplo práctico (stack: Node/Express backend, SPA frontend) — pasos:

Preparación

Añade soporte en backend para leer cookie además del token en header (acepta ambos para la transición).

Implementa endpoints /login que además de devolver token en body, también pongan cookie HttpOnly. En esta fase aún mantén localStorage en frontend.

Añade endpoint /logout que borre cookie.

Despliegue inicial (fase 1)

Despliega backend nuevo que acepta cookie pero sigue funcionando con token en header.

Actualiza frontend en staging para usar cookie (credentials: include) y probar.

Migración progresiva (fase 2)

En frontend de producción: primero versión que pone cookie al hacer login, pero todavía guarda token en localStorage. Esto garantiza compatibilidad si algo falla.

Monitorea logs y errores.

Cambio de comportamiento (fase 3)

Actualiza frontend para usar sólo cookies (elimina localStorage usage). Despliega a canary o a un % de usuarios si es posible.

Vigila métricas: tasa de login, errores 401, soporte al cliente.

Retiro gradual (fase 4)

Cuando la mayoría de usuarios usen cookies sin problemas, quita el fallback que buscaba token en header y elimina almacenamiento en localStorage del código.

Validaciones y monitoreo

Pruebas automáticas y manuales (login, logout, refresh).

Logs para fallos de autenticación y métricas de CSRF.

Comunicación a usuarios si hay cambios visibles.
Plan de rollback:

Mantén la versión antigua del backend disponible (o un endpoint de feature-flag) para volver en 1 click.

Si detectas aumento de errores críticos, activa el modo “compatibilidad” que acepta token tanto en cookie como en header y despliega rollback del frontend.

Tener scripts que invaliden cookies nuevos si necesitas forzar a usuarios a volver a login.
---

## Recursos Adicionales

- 📚 [MDN - HTTP Cookies](https://developer.mozilla.org/es/docs/Web/HTTP/Cookies)
- 📚 [OWASP - Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- 📚 [SameSite Cookie Explained](https://web.dev/samesite-cookies-explained/)
- 📚 [JWT Best Practices](https://blog.logrocket.com/jwt-authentication-best-practices/)

