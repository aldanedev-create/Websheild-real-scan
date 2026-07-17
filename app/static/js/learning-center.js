/**
 * WebShield Scanner - Learning Center JavaScript
 * Handles lesson listing, filtering, and search.
 */

(function() {
    'use strict';

    let currentCategory = 'all';
    let currentSearch = '';
    let filtersInitialized = false;
    let searchInitialized = false;

    /**
     * Load lessons
     */
    window.loadLessons = function() {
        window.api.learning.getLessons(currentCategory, null, currentSearch, 50, 0)
        .then(data => {
            if (data.success) {
                renderLessons(data.lessons);
                setupFilters();
                setupSearch();
            } else {
                console.error('Failed to load lessons:', data.message);
                showError('Failed to load lessons. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error loading lessons:', error);
            showError('An error occurred. Please try again.');
        });
    };

    /**
     * Render lessons
     */
    function renderLessons(lessons) {
        const container = document.getElementById('lessons-grid');
        if (!container) return;

        if (!lessons || lessons.length === 0) {
            container.innerHTML = `
                <div class="no-lessons">
                    <i class="fas fa-book-open"></i>
                    <p>No lessons found matching your criteria.</p>
                    <button class="btn btn-primary btn-sm mt-2" onclick="resetFilters()">Reset Filters</button>
                </div>
            `;
            return;
        }

        const isPremium = window.WebShield && window.WebShield.state && window.WebShield.state.isPremium;

        let html = '';
        lessons.forEach(lesson => {
            const category = String(lesson.category || 'general');
            const difficulty = String(lesson.difficulty || 'beginner');
            const badgeClass = 'badge-' + safeClass(category.replace('_', '-'));
            const difficultyClass = 'difficulty-' + safeClass(difficulty);
            const isLocked = lesson.is_premium && !isPremium;
            const lessonSummary = lesson.excerpt ||
                (lesson.content ? lesson.content.substring(0, 120) + '...' : 'Open this lesson to view the full learning material.');

            html += `
                <a href="/learning/${lesson.id}" class="lesson-card ${lesson.is_premium ? 'premium' : ''}">
                    <div>
                        <span class="lesson-badge ${badgeClass}">${escapeHtml(category.replace('_', ' '))}</span>
                        ${lesson.is_premium ? '<span class="lesson-badge badge-premium"><i class="fas fa-crown"></i> Premium</span>' : ''}
                        ${isLocked ? '<span class="locked"><i class="fas fa-lock"></i></span>' : ''}
                    </div>
                    <div class="lesson-title">${escapeHtml(lesson.title)}</div>
                    <div class="lesson-excerpt">${escapeHtml(lessonSummary)}</div>
                    <div class="lesson-meta">
                        <span class="difficulty ${difficultyClass}">${escapeHtml(difficulty)}</span>
                        <span><i class="far fa-clock"></i> ${lesson.reading_time || 10} min</span>
                        <span><i class="far fa-eye"></i> ${lesson.views || 0}</span>
                    </div>
                </a>
            `;
        });

        container.innerHTML = html;
    }

    /**
     * Setup category filters
     */
    function setupFilters() {
        const container = document.getElementById('category-filters');
        if (!container || filtersInitialized) return;
        filtersInitialized = true;

        container.querySelectorAll('.cat-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const category = this.dataset.category;

                // Update active state
                container.querySelectorAll('.cat-btn').forEach(b => {
                    b.classList.remove('active');
                });
                this.classList.add('active');

                currentCategory = category;
                loadLessons();
            });
        });
    }

    /**
     * Setup search
     */
    function setupSearch() {
        const searchInput = document.getElementById('search-lessons');
        if (!searchInput || searchInitialized) return;
        searchInitialized = true;

        const debouncedSearch = WebShield.debounce(function(value) {
            currentSearch = value.trim();
            loadLessons();
        }, 500);

        searchInput.addEventListener('input', function() {
            debouncedSearch(this.value);
        });
    }

    /**
     * Reset filters
     */
    window.resetFilters = function() {
        currentCategory = 'all';
        currentSearch = '';

        const searchInput = document.getElementById('search-lessons');
        if (searchInput) {
            searchInput.value = '';
        }

        const container = document.getElementById('category-filters');
        if (container) {
            container.querySelectorAll('.cat-btn').forEach(b => {
                b.classList.remove('active');
                if (b.dataset.category === 'all') {
                    b.classList.add('active');
                }
            });
        }

        loadLessons();
    };

    /**
     * Show error message
     */
    function showError(message) {
        const container = document.getElementById('lessons-grid');
        if (container) {
            container.innerHTML = `
                <div class="no-lessons">
                    <i class="fas fa-exclamation-triangle" style="color:#f44336;"></i>
                    <p>${escapeHtml(message)}</p>
                    <button class="btn btn-primary btn-sm mt-2" onclick="loadLessons()">Retry</button>
                </div>
            `;
        }
    }

    /**
     * Escape HTML
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function safeClass(text) {
        return String(text || '').toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'general';
    }

})();
