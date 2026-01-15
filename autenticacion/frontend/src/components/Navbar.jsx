import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Navbar = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="nav-brand">
        <Link to="/">🔐 Auth App</Link>
      </div>
      
      <div className="nav-links">
        {isAuthenticated() ? (
          <>
            <span className="user-greeting">Hola, {user?.name}</span>
            <Link to="/dashboard">Dashboard</Link>
            <button onClick={handleLogout} className="btn-logout">
              Cerrar Sesión
            </button>
          </>
        ) : (
          <>
            <Link to="/login">Iniciar Sesión</Link>
            <Link to="/register">Registrarse</Link>
          </>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
