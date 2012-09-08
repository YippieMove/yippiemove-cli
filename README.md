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


