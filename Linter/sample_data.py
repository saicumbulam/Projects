"""
Sample Data Generator
Creates sample instances of the model classes for demonstration.
"""

from datetime import datetime, timedelta
from models import User, Post, Product, Company, Employee


def create_sample_data():
    """Create and return sample data for all models."""

    # Create users
    user1 = User(1, "johndoe", "john@example.com", datetime(2023, 1, 15))
    user2 = User(2, "janesmit", "jane@example.com", datetime(2023, 3, 20))
    user3 = User(3, "bobwilson", "bob@example.com", datetime(2023, 6, 10))

    # Create posts
    post1 = Post(
        post_id=1,
        title="Getting Started with Python",
        content="Python is a versatile programming language perfect for beginners...",
        author=user1,
        created_at=datetime(2023, 2, 1),
        tags=["python", "programming", "tutorial"],
        published=True
    )

    post2 = Post(
        post_id=2,
        title="Advanced Jinja Templating",
        content="Jinja2 is a powerful templating engine for Python applications...",
        author=user1,
        created_at=datetime(2023, 3, 15),
        tags=["jinja", "templates", "python"],
        published=True
    )

    post3 = Post(
        post_id=3,
        title="Data Modeling Best Practices",
        content="When designing data models, consider normalization and relationships...",
        author=user2,
        created_at=datetime(2023, 4, 10),
        tags=["database", "modeling", "best-practices"],
        published=True
    )

    post4 = Post(
        post_id=4,
        title="Introduction to Web Development",
        content="Web development involves creating websites and web applications...",
        author=user3,
        created_at=datetime(2023, 7, 5),
        tags=["web", "development", "html", "css"],
        published=False
    )

    # Add posts to users
    user1.add_post(post1)
    user1.add_post(post2)
    user2.add_post(post3)
    user3.add_post(post4)

    # Create products
    products = [
        Product(1, "Laptop Pro 15", 1299.99, "High-performance laptop with 16GB RAM", "Electronics", 25, 4.5),
        Product(2, "Wireless Mouse", 29.99, "Ergonomic wireless mouse with USB receiver", "Accessories", 150, 4.2),
        Product(3, "Mechanical Keyboard", 89.99, "RGB mechanical keyboard with Cherry MX switches", "Accessories", 50,
                4.7),
        Product(4, "USB-C Hub", 49.99, "7-in-1 USB-C hub with HDMI and card reader", "Accessories", 0, 4.0),
        Product(5, "Monitor 27\"", 349.99, "4K UHD monitor with HDR support", "Electronics", 15, 4.6),
    ]

    # Create company and employees
    company = Company("TechCorp Solutions", "Software Development", 2015)

    employees = [
        Employee(101, "Alice Johnson", "Engineering", 95000.0, datetime(2020, 1, 15)),
        Employee(102, "Bob Martinez", "Engineering", 105000.0, datetime(2019, 6, 1)),
        Employee(103, "Carol White", "Marketing", 75000.0, datetime(2021, 3, 10)),
        Employee(104, "David Lee", "Sales", 80000.0, datetime(2020, 9, 5)),
        Employee(105, "Emma Davis", "Engineering", 98000.0, datetime(2021, 11, 20)),
        Employee(106, "Frank Brown", "HR", 70000.0, datetime(2022, 2, 14)),
    ]

    # Hire all employees
    for employee in employees:
        company.hire_employee(employee)

    return {
        'users': [user1, user2, user3],
        'posts': [post1, post2, post3, post4],
        'products': products,
        'company': company,
        'employees': employees
    }


if __name__ == "__main__":
    data = create_sample_data()

    print("Sample Data Created:")
    print(f"Users: {len(data['users'])}")
    print(f"Posts: {len(data['posts'])}")
    print(f"Products: {len(data['products'])}")
    print(f"Company: {data['company'].name}")
    print(f"Employees: {len(data['employees'])}")