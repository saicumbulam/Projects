"""
Sample Model Classes Project
This module contains various model classes demonstrating different design patterns.
"""

from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, field


class User:
    """Basic User model using traditional class definition."""

    def __init__(self, user_id: int, username: str, email: str, created_at: Optional[datetime] = None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.created_at = created_at or datetime.now()
        self.posts: List['Post'] = []

    def add_post(self, post: 'Post') -> None:
        """Add a post to the user's posts."""
        self.posts.append(post)

    def get_post_count(self) -> int:
        """Return the number of posts by this user."""
        return len(self.posts)

    def to_dict(self) -> dict:
        """Convert user to dictionary representation."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'post_count': self.get_post_count()
        }

    def __repr__(self) -> str:
        return f"User(id={self.user_id}, username='{self.username}')"


@dataclass
class Post:
    """Blog post model using dataclass."""

    post_id: int
    title: str
    content: str
    author: User
    created_at: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    published: bool = False

    def publish(self) -> None:
        """Mark the post as published."""
        self.published = True

    def add_tag(self, tag: str) -> None:
        """Add a tag to the post."""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> dict:
        """Convert post to dictionary representation."""
        return {
            'post_id': self.post_id,
            'title': self.title,
            'content': self.content,
            'author': self.author.username,
            'created_at': self.created_at.isoformat(),
            'tags': self.tags,
            'published': self.published
        }

    def __repr__(self) -> str:
        return f"Post(id={self.post_id}, title='{self.title}', author={self.author.username})"


@dataclass
class Product:
    """Product model for an e-commerce system."""

    product_id: int
    name: str
    price: float
    description: str
    category: str
    stock: int = 0
    rating: float = 0.0

    @property
    def is_available(self) -> bool:
        """Check if product is in stock."""
        return self.stock > 0

    @property
    def formatted_price(self) -> str:
        """Return formatted price with currency symbol."""
        return f"${self.price:.2f}"

    def update_stock(self, quantity: int) -> None:
        """Update stock quantity."""
        self.stock += quantity
        if self.stock < 0:
            self.stock = 0

    def to_dict(self) -> dict:
        """Convert product to dictionary representation."""
        return {
            'product_id': self.product_id,
            'name': self.name,
            'price': self.price,
            'formatted_price': self.formatted_price,
            'description': self.description,
            'category': self.category,
            'stock': self.stock,
            'rating': self.rating,
            'is_available': self.is_available
        }


class Company:
    """Company model with employees."""

    def __init__(self, name: str, industry: str, founded_year: int):
        self.name = name
        self.industry = industry
        self.founded_year = founded_year
        self.employees: List['Employee'] = []

    def hire_employee(self, employee: 'Employee') -> None:
        """Add an employee to the company."""
        self.employees.append(employee)
        employee.company = self

    def get_total_salary_expense(self) -> float:
        """Calculate total salary expense."""
        return sum(emp.salary for emp in self.employees)

    def get_employees_by_department(self, department: str) -> List['Employee']:
        """Get all employees in a specific department."""
        return [emp for emp in self.employees if emp.department == department]

    def to_dict(self) -> dict:
        """Convert company to dictionary representation."""
        return {
            'name': self.name,
            'industry': self.industry,
            'founded_year': self.founded_year,
            'employee_count': len(self.employees),
            'total_salary_expense': self.get_total_salary_expense()
        }


@dataclass
class Employee:
    """Employee model."""

    employee_id: int
    name: str
    department: str
    salary: float
    hire_date: datetime = field(default_factory=datetime.now)
    company: Optional[Company] = None

    def get_years_of_service(self) -> int:
        """Calculate years of service."""
        return (datetime.now() - self.hire_date).days // 365

    def to_dict(self) -> dict:
        """Convert employee to dictionary representation."""
        return {
            'employee_id': self.employee_id,
            'name': self.name,
            'department': self.department,
            'salary': self.salary,
            'hire_date': self.hire_date.isoformat(),
            'years_of_service': self.get_years_of_service(),
            'company': self.company.name if self.company else None
        }