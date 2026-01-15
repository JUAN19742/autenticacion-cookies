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