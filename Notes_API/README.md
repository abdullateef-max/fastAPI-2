1. Setup Postman
Download Postman: https://www.postman.com/downloads/

Create a new collection (e.g., "Notes API Tests").

2. Register a User (POST)
Request Setup:
Method: POST

URL: http://localhost:8000/register/

Headers:

Content-Type: application/json

Body (Raw JSON):

json
{
    "username": "desire_usernamre",
    "password": "securepassword123"
}
Expected Response (201 Created):
json
{
    "message": "User registered successfully"
}
3. Login & Get Token (POST)
Request Setup:
Method: POST

URL: http://localhost:8000/login/

Headers:

Content-Type: application/x-www-form-urlencoded

Body (x-www-form-urlencoded):

Key	Value
username	test_user
password	securepassword123
Expected Response (200 OK):
json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}
Save this token for authenticated requests.

4. Add a Note (POST - Authenticated)
Request Setup:
Method: POST

URL: http://localhost:8000/notes/

Headers:

Content-Type: application/json

Authorization: Bearer <your_token>

Body (Raw JSON):

json
{
    "title": "First Note",
    "content": "This is a secure note!",
    "date": "2023-10-20T12:00:00"
}
Expected Response (200 OK):
json
{
    "message": "Note added successfully"
}
5. Get All Notes (GET - Authenticated)
Request Setup:
Method: GET

URL: http://localhost:8000/notes/

Headers:

Authorization: Bearer <your_token>

Expected Response (200 OK):
json
[
    {
        "title": "First Note",
        "content": "This is a secure note!",
        "date": "2023-10-20T12:00:00"
    }
]
