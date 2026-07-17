import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { learningApi } from '../api/learningApi.js';
import '../styles/global.css';

const LearningCenter = () => {
  const [lessons, setLessons] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [category, setCategory] = useState('all');
  const [search, setSearch] = useState('');
  const [categories, setCategories] = useState([]);

  useEffect(() => {
    loadCategories();
    loadLessons();
  }, []);

  const loadCategories = async () => {
    try {
      const response = await learningApi.getCategories();
      if (response.success) {
        setCategories(response.categories || []);
      }
    } catch (err) {
      console.error('Categories error:', err);
    }
  };

  const loadLessons = async () => {
    setLoading(true);
    setError('');

    try {
      const response = await learningApi.getLessons({
        category: category !== 'all' ? category : undefined,
        search: search || undefined,
        limit: 50
      });

      if (response.success) {
        setLessons(response.lessons || []);
      } else {
        setError(response.message || 'Failed to load lessons.');
      }
    } catch (err) {
      console.error('Lessons error:', err);
      setError('An error occurred while loading lessons.');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearch(e.target.value);
    // Debounced search
    clearTimeout(window.searchTimeout);
    window.searchTimeout = setTimeout(loadLessons, 500);
  };

  const handleCategoryChange = (cat) => {
    setCategory(cat);
    setTimeout(loadLessons, 100);
  };

  const getBadgeClass = (cat) => {
    const classes = {
      owasp: 'badge-owasp',
      web_security: 'badge-web_security',
      secure_coding: 'badge-secure_coding',
      testing: 'badge-testing',
      api_security: 'badge-api_security'
    };
    return classes[cat] || 'badge-owasp';
  };

  const getDifficultyClass = (diff) => {
    return `difficulty-${diff}`;
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="loading-container">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-2 text-muted">Loading lessons...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">
          <i className="fas fa-graduation-cap"></i> Learning Center
        </h1>
        <div className="learning-search">
          <input
            type="text"
            placeholder="Search lessons..."
            value={search}
            onChange={handleSearch}
          />
        </div>
      </div>

      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="fas fa-exclamation-circle me-2"></i>
          {error}
          <button type="button" className="btn-close" onClick={() => setError('')}></button>
        </div>
      )}

      {/* Category Filters */}
      <div className="category-filters">
        <button
          className={`cat-btn ${category === 'all' ? 'active' : ''}`}
          onClick={() => handleCategoryChange('all')}
        >
          All
        </button>
        {categories.map(cat => (
          <button
            key={cat.name}
            className={`cat-btn ${category === cat.name ? 'active' : ''}`}
            onClick={() => handleCategoryChange(cat.name)}
          >
            {cat.name.replace('_', ' ')} ({cat.count})
          </button>
        ))}
      </div>

      {/* Lessons Grid */}
      <div className="lessons-grid">
        {lessons.length === 0 ? (
          <div className="no-lessons">
            <i className="fas fa-book-open"></i>
            <p>No lessons found matching your criteria.</p>
            <button 
              className="btn btn-primary btn-sm mt-2"
              onClick={() => { setCategory('all'); setSearch(''); loadLessons(); }}
            >
              Reset Filters
            </button>
          </div>
        ) : (
          lessons.map(lesson => (
              <Link
                key={lesson.id}
                to={`/learning/${lesson.id}`}
                className="lesson-card"
              >
                <div>
                  <span className={`lesson-badge ${getBadgeClass(lesson.category)}`}>
                    {lesson.category.replace('_', ' ')}
                  </span>
                </div>
                <div className="lesson-title">{lesson.title}</div>
                <div className="lesson-excerpt">
                  {lesson.excerpt || lesson.content?.substring(0, 120) + '...' || 'No description available.'}
                </div>
                <div className="lesson-meta">
                  <span className={getDifficultyClass(lesson.difficulty)}>
                    {lesson.difficulty}
                  </span>
                  <span><i className="far fa-clock"></i> {lesson.reading_time || 10} min</span>
                  <span><i className="far fa-eye"></i> {lesson.views || 0}</span>
                </div>
              </Link>
          ))
        )}
      </div>
    </div>
  );
};

export default LearningCenter;
