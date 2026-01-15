import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Home = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div className="home-container">
      <h1>🔐 Bienvenido a Auth App</h1>
      <p>
        Una aplicación completa de autenticación construida con React, Express.js y JWT.
        Aprende a implementar sistemas de autenticación seguros y profesionales.
      </p>

      {isAuthenticated() ? (
        <div className="home-buttons">
          <Link to="/dashboard" className="btn-primary">
            Ir al Dashboard
          </Link>
        </div>
      ) : (
        <div className="home-buttons">
          <Link to="/login" className="btn-primary">
            Iniciar Sesión
          </Link>
          <Link to="/register" className="btn-secondary">
            Crear Cuenta
          </Link>
        </div>
      )}

      <div className="features">
        <div className="feature-card">
          <h3>🔒 Seguro</h3>
          <p>Implementa las mejores prácticas de seguridad con JWT, bcrypt y validación en cliente y servidor.</p>
        </div>

        <div className="feature-card">
          <h3>⚛️ React Moderno</h3>
          <p>Utiliza React 18 con Hooks, Context API y React Router v6 para una experiencia de usuario fluida.</p>
        </div>

        <div className="feature-card">
          <h3>🚀 Express Backend</h3>
          <p>API RESTful construida con Express.js y manejo profesional de autenticación con middleware.</p>
        </div>

        <div className="feature-card">
          <h3>🎨 UI Moderna</h3>
          <p>Interfaz limpia y responsiva con CSS moderno y diseño enfocado en la experiencia del usuario.</p>
        </div>

        <div className="feature-card">
          <h3>🛡️ Rutas Protegidas</h3>
          <p>Implementación de rutas privadas que solo usuarios autenticados pueden acceder.</p>
        </div>

        <div className="feature-card">
          <h3>📱 Responsive</h3>
          <p>Diseño adaptable que funciona perfectamente en dispositivos móviles, tablets y desktop.</p>
        </div>
      </div>
    </div>
  );
};

export default Home;
