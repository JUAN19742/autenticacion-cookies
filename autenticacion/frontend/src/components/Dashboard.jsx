import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { user } = useAuth();

  return (
    <div className="dashboard">
      <h1>Bienvenido, {user?.name}! 🎉</h1>
      
      <div className="user-info">
        <h2>Tu información</h2>
        <p><strong>Email:</strong> {user?.email}</p>
        <p><strong>Rol:</strong> {user?.role}</p>
        <p><strong>ID:</strong> {user?.id}</p>
        <p><strong>Miembro desde:</strong> {new Date(user?.createdAt).toLocaleDateString('es-ES')}</p>
      </div>
      
      <div className="dashboard-content">
        <h2>🔒 Contenido Protegido</h2>
        <p>Solo los usuarios autenticados pueden ver esta información.</p>
        <p>Este es un área segura de la aplicación donde puedes implementar funcionalidades exclusivas para usuarios registrados.</p>
        
        <div style={{ marginTop: '2rem' }}>
          <h3>Funcionalidades disponibles:</h3>
          <ul style={{ marginLeft: '1.5rem', marginTop: '1rem' }}>
            <li>Gestión de perfil de usuario</li>
            <li>Acceso a contenido premium</li>
            <li>Configuración de preferencias</li>
            <li>Historial de actividad</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
