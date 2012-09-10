yippiemove-cli
==============

YippieMove Command Line Interface (CLI) written in Python.

## Using Tokens

To use the YippieMove API you'll need a user's access token (usually yours). 
For each request you make to the YippieMove API you'll need to provide the 
access token, though we provide two ways to do this using this utility.

You may provide the token per each usage:

    $ ./yippiemove.py --token=ceaba709b1 read email_account 76

Or if you'll be making multiple actions using the same token, you may set 
the token, which will be saved in a file named `.ymo_token` (write-access 
is required). After doing so you are not required to specify the token 
manually each time.

    $ ./yippiemove.py token set ceaba709b1
    Token set as ceaba709b1

To read the current saved token, you may use `token get`:

    $ ./yippiemove.py token get
    Token is: ceaba709b1

To remove the current token:

    $ ./yippiemove.py token delete
    Token removed.

## Using the Wizard

The simplest way to create a new email transfer using this utility is to 
use the wizard:

    $ ./yippiemove.py wizard

This will guide you through the process of choosing the source and destination 
email accounts, providing login credentials for them, confirming they are 
correct, starting YippieMove's indexing of the account, and choosing which 
email folders to transfer to the destination account. Finally, you can then 
issue a payment for the new transfer to have it start processing as soon 
as possible.

## Low-level CRUD methods

You can use low-level CRUD (create, read, update, delete) methods to interact
with objects on the YippieMove API.

### Create

To create objects, you may use the `create` subcommand:

    $ ./yippiemove.py create order
    {
        "batches": [],
        "created_at": "2012-09-10T08:24:50.556",
        "credits": 0,
        "move_jobs": [
            {
                "link": "/api/users/3/move_jobs/5/"
            }
        ],
        "link": "/api/users/3/orders/10/",
        "payments": [],
        "owner": {
            "link": "/api/users/3/"
        },
        "id": 10
    }

The response is the JSON-encoded representation of the object you've
created. Take note of the object's ID &mdash; you can use this to
make further operations on this object.

### Read

To read objects, use the `read` subcommand and provide the object's
type and its ID:

    $ ./yippiemove.py read order 10
    {
        "batches": [],
        "created_at": "2012-09-10T08:24:50.556",
        "credits": 0,
        "move_jobs": [
            {
                "link": "/api/users/3/move_jobs/5/"
            }
        ],
        "link": "/api/users/3/orders/10/",
        "payments": [],
        "owner": {
            "link": "/api/users/3/"
        },
        "id": 10
    }

### Update

To update objects, use the `update` subcommand and provide the object's
type, its ID, and the properties you'd like to change:

    $ ./yippiemove.py update email_account 68 login=yippiemove

### Delete

To delete objects, use the `delete` subcommand and provide the object's
type and its ID. Please note that in most cases with the YippieMove API,
you cannot delete objects after they've been created.

    $ ./yippiemove.py delete email_account 68

### List

To obtain a list of objects, use the `list` subcommand and provide the
object's type and specific details needed for that query. For example,
to obtain a list of `email_account` you must provide the `move_job` you
want to list the accounts of. If you haven't provided the necessary
properties an error will show, telling you exactly which property you
were missing.

    $ ./yippiemove.py list email_account move_job=77