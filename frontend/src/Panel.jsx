import { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function Panel({ user, onLogout }) {
  const [filters, setFilters] = useState({
    campaignGroupId: '',
    status: 'sale',
    from: '',
    to: ''
  });
  
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [clickData, setClickData] = useState({});
  const [spend, setSpend] = useState(null);

  // Setup axios interceptor to add token to all requests
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }

    // Response interceptor to handle 401 errors
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401 || error.response?.status === 403) {
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          delete axios.defaults.headers.common['Authorization'];
          onLogout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, [onLogout]);

  const handleInputChange = (field, value) => {
    setFilters(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setClickData({});
    setSpend(null);

    const trimmedCampaignGroupId = filters.campaignGroupId.trim();
    if (!trimmedCampaignGroupId || !filters.from || !filters.to) {
      setLoading(false);
      setError('Необходимо ввести Campaign Group ID и обе даты');
      return;
    }

    try {
      const requestBody = {
        range: {
          from: filters.from,
          to: filters.to,
          timezone: 'Europe/Kyiv',
          interval: ''
        },
        limit: 1000,
        offset: 0,
        columns: [
          'sub_id',
          'affiliate_network',
          'offer',
          'sub_id_3',
          'status',
          'revenue',
          'status_history',
          'datetime',
          'country_flag',
          'country'
        ],
        filters: [
          {
            name: 'campaign_group_id',
            operator: 'EQUALS',
            expression: trimmedCampaignGroupId
          },
          {
            name: 'status',
            operator: 'EQUALS',
            expression: filters.status
          }
        ],
        sort: [
          {
            name: 'status',
            order: 'DESC'
          }
        ]
      };

      const response = await axios.post('/api/conversions/log', requestBody);
      setData(response.data);
      
      await fetchSpend(trimmedCampaignGroupId, filters.from, filters.to);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Ошибка при загрузке данных');
      setData(null);
      setSpend(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchSpend = async (campaignGroupId, dateFrom, dateTo) => {
    try {
      const requestBody = {
        dimensions: ['campaign_group'],
        measures: ['cost'],
        filters: {
          AND: [
            {
              name: 'cost',
              operator: 'NOT_EQUAL',
              expression: '0'
            },
            {
              name: 'campaign_group_id',
              operator: 'EQUALS',
              expression: campaignGroupId
            }
          ]
        },
        sort: [],
        limit: 1000,
        offset: 0,
        extended: true,
        range: {
          from: dateFrom,
          to: dateTo,
          timezone: 'Europe/Kyiv',
          interval: 'custom_date_range'
        },
        summary: true
      };

      const response = await axios.post('/api/report/build', requestBody);
      const spendValue = response.data?.summary?.cost || 0;
      setSpend(spendValue);
    } catch (err) {
      console.error('Error fetching spend:', err);
      setSpend(null);
    }
  };

  const handleReset = () => {
    setFilters({
      campaignGroupId: '',
      status: 'sale',
      from: '',
      to: ''
    });
    setData(null);
    setError(null);
    setClickData({});
    setSpend(null);
  };

  const handleClickDatetime = async (subId) => {
    if (clickData[subId]?.datetime || clickData[subId]?.loading) {
      return;
    }

    setClickData(prev => ({
      ...prev,
      [subId]: { loading: true, error: null, datetime: prev[subId]?.datetime || null }
    }));

    try {
      const requestBody = {
        range: {
          from: '',
          to: '',
          timezone: 'Europe/Kyiv',
          interval: 'all_time'
        },
        limit: '1000',
        offset: '0',
        columns: ['sub_id', 'datetime'],
        filters: [
          {
            name: 'sub_id',
            operator: 'EQUALS',
            expression: subId
          }
        ],
        sort: []
      };

      const response = await axios.post('/api/clicks/log', requestBody);
      const datetime = response.data?.rows?.[0]?.datetime || 'Нет данных';

      setClickData(prev => ({
        ...prev,
        [subId]: { loading: false, error: null, datetime }
      }));
    } catch (err) {
      const message = err.response?.data?.error || err.message || 'Ошибка при получении даты клика';
      setClickData(prev => ({
        ...prev,
        [subId]: { loading: false, error: message, datetime: null }
      }));
    }
  };

  const getStatusClass = (status) => {
    return status === 'sale' ? 'status-sale' : 'status-lead';
  };

  const getDateHighlights = (deposit, click) => {
    if (!deposit || !click) {
      return { depositStyle: {}, clickStyle: {} };
    }

    const parse = (value) => new Date(value.replace(' ', 'T'));
    const depositDate = parse(deposit);
    const clickDate = parse(click);

    if (Number.isNaN(depositDate.getTime()) || Number.isNaN(clickDate.getTime())) {
      return { depositStyle: {}, clickStyle: {} };
    }

    const sameMonth =
      depositDate.getFullYear() === clickDate.getFullYear() &&
      depositDate.getMonth() === clickDate.getMonth();

    if (sameMonth) {
      const style = { backgroundColor: '#d4edda' };
      return { depositStyle: style, clickStyle: style };
    }

    return {
      depositStyle: { backgroundColor: '#d4edda' },
      clickStyle: { backgroundColor: '#f8d7da' }
    };
  };

  const calculateTotalRevenue = () => {
    if (!data || !data.rows) return 0;
    return data.rows.reduce((total, row) => {
      const revenue = parseFloat(row.revenue) || 0;
      return total + revenue;
    }, 0);
  };

  const isSubmitDisabled = loading || !filters.campaignGroupId.trim() || !filters.from || !filters.to;

  return (
    <div className="container">
      <div className="header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <div>
            <h1>Conversion Log Panel</h1>
            <p>Панель для отображения логов конверсий из Keitaro</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <span style={{ color: '#666', fontSize: '14px' }}>
              {user?.username} ({user?.role})
            </span>
            <button 
              onClick={onLogout}
              className="btn btn-secondary"
              style={{ padding: '8px 16px', fontSize: '14px' }}
            >
              Выйти
            </button>
          </div>
        </div>
      </div>

      <form className="filters" onSubmit={handleSubmit}>
        <h2>Фильтры</h2>
        
        <div className="filter-group">
          <div className="filter-item">
            <label htmlFor="campaignGroupId">Campaign Group ID:</label>
            <input
              id="campaignGroupId"
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={filters.campaignGroupId}
              onChange={(e) => handleInputChange('campaignGroupId', e.target.value.replace(/\D/g, ''))}
              placeholder="Введите ID группы кампаний"
              required
            />
          </div>

          <div className="filter-item">
            <label htmlFor="from">Date From:</label>
            <input
              id="from"
              type="date"
              lang="ru-RU"
              placeholder="дд.мм.гггг"
              value={filters.from}
              onChange={(e) => handleInputChange('from', e.target.value)}
              required
            />
          </div>

          <div className="filter-item">
            <label htmlFor="to">Date To:</label>
            <input
              id="to"
              type="date"
              lang="ru-RU"
              placeholder="дд.мм.гггг"
              value={filters.to}
              onChange={(e) => handleInputChange('to', e.target.value)}
              required
            />
          </div>
        </div>

        <div className="button-group">
          <button type="submit" className="btn btn-primary" disabled={isSubmitDisabled}>
            {loading ? 'Загрузка...' : 'Загрузить данные'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={handleReset}>
            Сбросить
          </button>
        </div>
      </form>

      {error && (
        <div className="error">
          Ошибка: {error}
        </div>
      )}

      {loading && (
        <div className="loading">
          Загрузка данных...
        </div>
      )}

      {data && !loading && (
        <div className="table-container">
          {data.total > 0 ? (
            <>
              <div className="info">
                Найдено записей: {data.total}
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Sub ID</th>
                    <th>Affiliate Network</th>
                    <th>Offer</th>
                    <th>Sub ID 3</th>
                    <th>Status</th>
                    <th>Revenue</th>
                    <th>Country</th>
                    <th>Status History</th>
                    <th>Дата и время депозита</th>
                    <th>Дата и время клика</th>
                  </tr>
                </thead>
                <tbody>
                  {data.rows.map((row, index) => {
                    const clickInfo = clickData[row.sub_id];
                    const highlights = getDateHighlights(row.datetime, clickInfo?.datetime);

                    return (
                      <tr key={index}>
                        <td>{row.sub_id}</td>
                        <td>{row.affiliate_network}</td>
                        <td>{row.offer}</td>
                        <td>{row.sub_id_3}</td>
                        <td>
                          <span className={`status-badge ${getStatusClass(row.status)}`}>
                            {row.status}
                          </span>
                        </td>
                        <td className="revenue">{row.revenue}</td>
                        <td>{row.country_flag} {row.country}</td>
                        <td>
                          <pre style={{ whiteSpace: 'pre-wrap', fontSize: '12px' }}>
                            {row.status_history}
                          </pre>
                        </td>
                        <td style={highlights.depositStyle}>
                          {row.datetime}
                        </td>
                        <td style={highlights.clickStyle}>
                          {clickInfo?.loading ? (
                            <span>Загрузка...</span>
                          ) : clickInfo?.datetime ? (
                            clickInfo.datetime
                          ) : clickInfo?.error ? (
                            <span style={{ color: 'red', fontSize: '12px' }}>
                              {clickInfo.error}
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-link"
                              onClick={() => handleClickDatetime(row.sub_id)}
                            >
                              узнать
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="revenue-summary">
                <div>
                  <strong>Общая сумма Revenue:</strong> {calculateTotalRevenue().toFixed(2)}
                </div>
                {spend !== null && (
                  <div>
                    <strong>Spend:</strong> {spend.toFixed(3)}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="info">
              Данные не найдены
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default Panel;

