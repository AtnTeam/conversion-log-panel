import { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function Users({ user }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [newUser, setNewUser] = useState({
    login: '',
    password: '',
    campaignGroupId: ''
  });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.get('/api/users');
      setUsers(response.data.users || []);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Ошибка при загрузке пользователей');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (field, value) => {
    setNewUser(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!newUser.login || !newUser.password || !newUser.campaignGroupId) {
      setError('Все поля обязательны');
      return;
    }

    // Validate campaign group ID is numeric
    if (!/^\d+$/.test(newUser.campaignGroupId)) {
      setError('Campaign Group ID должен быть числом');
      return;
    }

    setLoading(true);
    try {
      await axios.post('/api/users', {
        login: newUser.login,
        password: newUser.password,
        campaignGroupId: newUser.campaignGroupId
      });
      setSuccess('Пользователь успешно добавлен');
      setNewUser({ login: '', password: '', campaignGroupId: '' });
      setShowAddForm(false);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Ошибка при добавлении пользователя');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm('Вы уверены, что хотите удалить этого пользователя?')) {
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await axios.delete(`/api/users/${id}`);
      setSuccess('Пользователь успешно удален');
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Ошибка при удалении пользователя');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      const date = new Date(dateString);
      return date.toLocaleString('ru-RU');
    } catch {
      return dateString;
    }
  };

  return (
    <>
      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {success && (
        <div className="success">
          {success}
        </div>
      )}

      <div className="filters" style={{ marginBottom: '20px', padding: '15px' }}>
        <button
          onClick={() => {
            setShowAddForm(!showAddForm);
            setError('');
            setSuccess('');
            setNewUser({ login: '', password: '', campaignGroupId: '' });
          }}
          className="btn btn-primary"
        >
          {showAddForm ? 'Отменить' : 'Добавить нового пользователя'}
        </button>
      </div>

      {showAddForm && (
        <form className="filters" onSubmit={handleAddUser} style={{ marginBottom: '30px' }}>
          <h2>Добавить пользователя</h2>
          
          <div className="filter-group">
            <div className="filter-item">
              <label htmlFor="login">Логин:</label>
              <input
                id="login"
                type="text"
                value={newUser.login}
                onChange={(e) => handleInputChange('login', e.target.value)}
                placeholder="Введите логин"
                required
                disabled={loading}
              />
            </div>

            <div className="filter-item">
              <label htmlFor="password">Пароль:</label>
              <input
                id="password"
                type="password"
                value={newUser.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Введите пароль"
                required
                disabled={loading}
              />
            </div>

            <div className="filter-item">
              <label htmlFor="campaignGroupId">Campaign Group ID:</label>
              <input
                id="campaignGroupId"
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={newUser.campaignGroupId}
                onChange={(e) => handleInputChange('campaignGroupId', e.target.value.replace(/\D/g, ''))}
                placeholder="Введите Campaign Group ID"
                required
                disabled={loading}
              />
            </div>
          </div>

          <div className="button-group">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Сохранение...' : 'Сохранить'}
            </button>
          </div>
        </form>
      )}

      {loading && !showAddForm && (
        <div className="loading">
          Загрузка пользователей...
        </div>
      )}

      {!loading && (
        <div className="table-container">
          {users.length > 0 ? (
            <>
              <div className="info">
                Всего пользователей: {users.length}
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Логин</th>
                    <th>Пароль</th>
                    <th>Campaign Group ID</th>
                    <th>Дата создания</th>
                    <th>Действия</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id}>
                      <td>{user.id}</td>
                      <td>{user.login}</td>
                      <td>{user.password_plain || 'N/A'}</td>
                      <td>{user.campaign_group_id}</td>
                      <td>{formatDate(user.created_at)}</td>
                      <td>
                        <button
                          onClick={() => handleDeleteUser(user.id)}
                          className="btn btn-secondary"
                          disabled={loading}
                        >
                          Удалить
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <div className="info">
              Пользователи не найдены
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default Users;

