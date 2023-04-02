# internship SaaS Backend API

## Description

This SaaS application, built using Django and DRF with a SQLite database, offers custom registration managed by an admin user. Users log in using their email and password, with IP checking for added security. If logging in from a different IP, users are sent an email to verify the login. The application has three types of users: superadmins, admins, and regular users. Superadmins can assign admins, create, activate and deactivate companies, while every admin has access to their own company only. Admins can send registration invites and create tasks for users. Users can create tasks for themselves or others, and notifications are sent for unfinished tasks. Analytics for all tasks are also available, and users receive email notifications for new tasks assigned to them. All users have their own profiles with their information that can be changed and the task count.

It's deployed on pythonanywhere.com and it's frontend is built in angular. You can check it in the repository https://github.com/NemanjaNecke/admin and on https://admin-intern.firebaseapp.com/

## Run

```
git clone https://github.com/NemanjaNecke/internship
cd internship
```

Create a virtual environment to install the project dependencies.

```
virtualenv venv
```

Activate the virtual environment using the following command if on windows:

```
venv/Scripts/activate
```

Install the project dependencies using `pip`. The dependencies are listed in the `requirements.txt`

```
pip install -r requirements.txt
```

Then:

```
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

then add your user

### Run tests

```
python manage.py test accounts/
```

### Django models

* Custom user model - Account model:
  * email
  * first_name
  * last_name
  * is_active
  * is_staff
* IP address model
  * ip_address
  * account - Foreign Key to Account model in order to save IP instances as related
  * verified

### API Endpoints

API is browsable and supports HTML forms, default content-type is application/json

#### Company

> GET, POST companies/

* Get provides a list of companies and can only be accessed by the super admin user
* Post creates a company and only a super admin can use post also

![1671111401324](image/README/1671111401324.png)

or

{
    "name": "",
    "admin": null,
    "active_until": null
}

* Default value for active until is 3 months and it doesn't have to be provided in post request

> GET, PUT companies/`<name>`/

* Detail view for companies uses company name as a parameter in URL
* Put request deactivates the company

![1671111700897](image/README/1671111700897.png)

or

{
    "id": "df3e4bca-b344-4d5a-9d2a-7b7909513218",
    "name": "new",
    "admin": "2ae99046-60c0-4354-abac-2f5e45438e19",
    "active_until": "2023-03-15T14:25:01.878948Z",
    "is_active": true,
    "accounts": []
}

#### Invites

> GET, POST, HEAD, OPTIONS invites/

![1671110864859](image/README/1671110864859.png)

or

```
{
    "email": "",
    "invited_by": null,
    "accepted": false
}
```

* Invites can only be created by company admin user.
* Creating an invite generates an email which is sent automatically with registration link

#### Register a user account

> POST auth/register/`<uidb64>`/`<token>`

![1670638348774](image/README/1670638348774.png)

or

```
{
    "username": "",
    "email": "",
    "password1": "",
    "password2": "",
    "first_name": "",
    "last_name": ""
}
```

* Registration automatically saves and verifies user's IP address
* In order to register correctly user has to verify the email address with confirmation email which is sent via console.backend
* When email is verified the user is redirected to login URL
* Registration only works with invite which generates the correct register link which is then sent in email
* View checks arguments from the URL to see if the right user is trying to register and decodes token and uid parameters from the URL
* Register view automatically sets the invite as accepted when the user visits the link

#### Login user

Login is done with email address

> POST auth/login/

![1670638557644](image/README/1670638557644.png)

or

```
{
    "email": "",
    "password": ""
}
```

* If user tries to login from different IP it is needed to verify that IP address via email
* Response is plain JSON that IP is verified

#### Password Reset

> POST auth/password/reset/

![1670640012817](image/README/1670640012817.png)

or

```
{
    "email": ""
}
```

* Returns a success or fail message and sends an email with password reset link

> POST auth/password/reset/confirm/

![1670640243677](image/README/1670640243677.png)

or

```
{
    "new_password1": "",
    "new_password2": "",
    "uid": "",
    "token": ""
}
```

* View that is generated with email confirmation, should be handled from front end as it needs a token and UID passed from user instance

#### User Endpoint

> GET auth/ user/

* User needs to be logged in to access this endpoint. Only username and personal info is editable.
* Accepts PUT and PATCH requests
* `/tasks/notification_email`: Sends a notification email to the user about their tasks.
* `/tasks/notification_count/`: Returns the count of notification emails that the user has received.
* `/tasks/analytics`: Returns the analytics data for tasks.
* `/auth/ip-address`: Returns the IP address of the user.
* `/auth/register/admin/`: Creates a new company administrator account.
* `/auth/accounts/admin/`: Returns a list of all company administrator accounts.
* `/auth/accounts/admin/<pk>`: Updates the details of a specific company administrator account.
* `/auth/accounts/account/`: Returns the details of the user's account.
* `/auth/accounts/all/`: Returns a list of all user accounts.
* `/invites/`: Lists all pending invitations or creates a new invitation.
* `/invites/<pk>/`: Retrieves or deletes a specific invitation.
* `/tasks/`: Lists all tasks or creates a new task.
* `/tasks/<pk>/`: Retrieves, updates or deletes a specific task.
* `/auth/password/reset/`: Sends an email to the user with a password reset link.
* `/auth/password/reset/confirm/<slug:uidb64>/<slug:token>/`: Resets the user's password.
* `/auth/registration/resend-email/`: Resends the verification email to the user.
* `/auth/ip-address/activate-ip/<uidb64>/<token>`: Activates the user's IP address.
* `/auth/`: Provides authentication endpoints for login, logout, and password change.
* `/auth/account-confirm-email/`: Sends an email to the user to confirm their email address.
