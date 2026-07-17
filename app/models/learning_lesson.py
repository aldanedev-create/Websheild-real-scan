# -*- coding: utf-8 -*-

"""
WebShield Scanner - Learning Lesson Model
Manages educational content for the learning center.
"""

from datetime import datetime
from extensions import db


class LearningLesson(db.Model):
    """Learning lesson model for security education content."""
    
    __tablename__ = 'learning_lessons'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Lesson details
    title = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, index=True)
    category = db.Column(db.String(50), nullable=False, index=True)
    # owasp, web_security, secure_coding, testing, api_security, etc.
    
    # Content
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.Text)
    
    # Metadata
    difficulty = db.Column(db.String(20), default='beginner', index=True)
    # beginner, intermediate, advanced
    
    # Media
    image_url = db.Column(db.String(500))
    video_url = db.Column(db.String(500))
    
    # Ordering
    order = db.Column(db.Integer, default=0, index=True)
    
    # Premium
    is_premium = db.Column(db.Boolean, default=False, index=True)
    
    # Statistics
    views = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    reading_time = db.Column(db.Integer, default=15)  # Minutes
    
    # References
    related_lessons = db.Column(db.JSON)  # List of lesson IDs
    tags = db.Column(db.JSON)  # List of tags
    
    # Status
    is_published = db.Column(db.Boolean, default=True, index=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, title, category, content, **kwargs):
        """Initialize a new learning lesson."""
        self.title = title.strip()
        self.category = category.lower()
        self.content = content
        self.slug = self.generate_slug(title)
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def generate_slug(self, title):
        """Generate a URL-friendly slug from the title."""
        import re
        from unicodedata import normalize
        
        # Convert to lowercase and remove accents
        slug = normalize('NFKD', title.lower())
        slug = slug.encode('ascii', 'ignore').decode('ascii')
        
        # Replace spaces and special characters with hyphens
        slug = re.sub(r'[^a-z0-9]+', '-', slug)
        slug = re.sub(r'-+', '-', slug)
        slug = slug.strip('-')
        
        # Ensure uniqueness
        if self.slug and self.slug == slug:
            return slug
        
        # Check if slug exists, add number if needed
        existing = LearningLesson.query.filter_by(slug=slug).first()
        if existing and existing.id != self.id:
            counter = 1
            while True:
                new_slug = f"{slug}-{counter}"
                if not LearningLesson.query.filter_by(slug=new_slug).first():
                    return new_slug
                counter += 1
        
        return slug
    
    def increment_views(self):
        """Increment the view count."""
        self.views += 1
        self.updated_at = datetime.utcnow()
    
    def increment_likes(self):
        """Increment the like count."""
        self.likes += 1
        self.updated_at = datetime.utcnow()
    
    def is_accessible(self, user=None):
        """Check if the lesson is accessible to the user."""
        if not self.is_premium:
            return True
        if user and user.is_premium():
            return True
        return False
    
    def to_dict(self):
        """Convert lesson to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'slug': self.slug,
            'category': self.category,
            'content': self.content,
            'excerpt': self.excerpt,
            'difficulty': self.difficulty,
            'image_url': self.image_url,
            'video_url': self.video_url,
            'order': self.order,
            'is_premium': self.is_premium,
            'views': self.views,
            'likes': self.likes,
            'reading_time': self.reading_time,
            'tags': self.tags,
            'is_published': self.is_published,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_preview_dict(self):
        """Convert lesson to preview dictionary (limited content)."""
        return {
            'id': self.id,
            'title': self.title,
            'slug': self.slug,
            'category': self.category,
            'excerpt': self.excerpt,
            'difficulty': self.difficulty,
            'image_url': self.image_url,
            'order': self.order,
            'is_premium': self.is_premium,
            'reading_time': self.reading_time,
            'tags': self.tags
        }
    
    def __repr__(self):
        return f'<LearningLesson {self.id}: {self.title}>'
