import React, { useState } from 'react';
import './App.css';

function App() {
  const [isLogin, setIsLogin] = useState(true);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const data = isLogin ? {
      username: formData.get('username'),
      password: formData.get('password'),
    } : {
      username: formData.get('username'),
      password: formData.get('password'),
      email: formData.get('email'),
    };

    try {
      const endpoint = isLogin ? 'login' : 'register';
      const response = await fetch(`http://localhost:8081/api/auth/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(errorData?.message || 'Failed');
      }

      if (isLogin) {
        const { token } = await response.json();
        localStorage.setItem('token', token);
        alert('Login successful!');
      } else {
        alert('Registration successful!');
        setIsLogin(true);
      }
    } catch (err) {
      alert(err instanceof Error ? err.message : (isLogin ? 'Login failed' : 'Registration failed'));
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Authentication System</h1>
      </header>
      <main>
        <div className="auth-container">
          <div className="auth-tabs">
            <button 
              className={isLogin ? 'active' : ''} 
              onClick={() => setIsLogin(true)}
            >
              Login
            </button>
            <button 
              className={!isLogin ? 'active' : ''} 
              onClick={() => setIsLogin(false)}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="auth-form">
            <h2>{isLogin ? 'Login' : 'Register'}</h2>
            
            <div className="form-group">
              <label>Username:</label>
              <input name="username" type="text" required />
            </div>

            {!isLogin && (
              <div className="form-group">
                <label>Email:</label>
                <input name="email" type="email" required />
              </div>
            )}

            <div className="form-group">
              <label>Password:</label>
              <input name="password" type="password" required />
            </div>

            <button type="submit">
              {isLogin ? 'Login' : 'Register'}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

export default App;
