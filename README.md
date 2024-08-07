# DailyExpensesSharingApplication

## Overview

This Django project provides an API for tracking expenses, user management, and generating balance sheets. It includes user authentication using tokens stored in cookies and supports various operations related to expenses and users.

## Project Structure

The project is organized into the following folders:

- **`split_expense/`**: Contains the core functionality related to expense splitting.
- **`expenses/`**: Manages the expense models and views.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Nehapal7791/DailyExpensesSharingApplication.git
   cd splitExpenses
   ```

2. **Create and Activate a Virtual Environment**

   ```bash
    python -m venv venv
    source venv/bin/activate    # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**

   ```bash
    pip install -r requirements.txt
   ```

4. **Set Up the Database**

5. **Apply Migrations**

   ```bash
   python manage.py migrate
   ```

6. **Create a Superuser (Optional)**

   To manage the project through Django's admin interface, create a superuser account:

   ```bash
    python manage.py createsuperuser
   ```

7. **Run the Development Server**
   ```bash
    python manage.py createsuperuser
   ```
8. **Start the Django development server:**
   ```bash
   python manage.py runserver
   ```

## API Endpoints

### Authentication

- **Register User**

  **URL:** `/register/`  
   **Method:** `POST`  
   **Request Body:**

  ```json
  {
    "username": "string",
    "password": "string",
    "email": "string"
  }
  ```

  #Response

```json
{
  "token": "string",
  "user_id": "integer",
  "email": "string"
}
```

**Login User**

URL: /login/
Method: POST
Request Body :
{
"username": "string",
"password": "string"
}
Response Body :
{
"user_id": "integer",
"email": "string"
}
Note: Token will be set as an HTTP-only cookie named auth_token.

## CREATE EXPENSE

**URL:** http://localhost:8000/api/expenses/

```json
{
    "title": "Dinner",
    "amount": 100.00,
    "date": "2024-07-29",
    "split_method": "EXACT",
    "participants": [
        {"participant": 1, "amount_owed": 33.33},
        {"participant": 2, "amount_owed": 33.33},
        {"participant": 3, "amount_owed": 33.34}
    ]
}
// ===FOR EQUAL
{
    "title": "DRINKS",
    "amount": 500.00,
    "date": "2024-07-29",
    "split_method": "EQUAL",
    "participants": [
        {"participant": 1},
        {"participant": 2},
        {"participant": 3}
    ]
}
//======FOR PERCENTAGE
{
    "title": "Dinner",
    "amount": 100.00,
    "date": "2024-07-29",
    "split_method": "PERCENTAGE",
    "participants": [
        {
            "participant": 2,
            "percentage_owed": 55.00
        },
        {
            "participant": 3,
            "percentage_owed": 45.00
        }
    ]
}
```

**List User Expenses**

URL: /user-expenses/
Method: GET
Headers:

Authorization: Token <token> (or token in cookies)

**Overall Expenses**

URL: /overall-expenses/
Method: GET
Headers:

Authorization: Token <token> (or token in cookies)

**User Balance**

URL: /user-balance/
Method: GET
Headers:

Authorization: Token <token> (or token in cookies)

**To download Balancesheet**
**URL:** - http://localhost:8000/api/download-balance-sheet/
Method: GET
Query Params:

user_id (optional)
Headers:
Authorization: Token <token> (or token in cookies)

Response: CSV file download with columns: User, Total Paid, Total Owed, Net Balance, Balances with Others.
