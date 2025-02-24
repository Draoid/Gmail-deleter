# Shell Gmail

Getting started
---------------

This script will help you search for emails, open and delete unnecessary emails on gmail. It will give you the option to delete all emails, emails from a specific category, and emails from a specific user. It also has additional features for emptying the trash, deleting spam emails, getting statistics on the size of emails, or displaying the frequency of sent/received emails from a specific user.


Prerequisites
-------------

 - Python
 - The [pip](https://pypi.python.org/pypi/pip) package management tool for Python
 - Access to Internet and a web browser
 - A Google account with Gmail account enabled
 - matplotlib for Python


Turn on Gmail API
-----------------

Follow the [instructions](https://developers.google.com/gmail/api/quickstart/python#step_1_turn_on_the_api_name)

Installation
------------

 - Optional: Create a virtual environment

 - Download json file from gmail api and save as client.json to the root folder of the project

 - Run: `pip install --upgrade google-api-python-client`


(Check requirements.txt for additional informations about requirements for installation)

Usage
-----

 - Copy json file generated from Gmail API to the repository directory


Run script inside *src* folder with:

`python gmail_deleter.py` or
`python gmail_search.py`

You can add extra options -s or --secret with a path to your "credentials.json" file.

`python gmail_deleter.py -s credentials.json`

The script provides the following options:
 - delete all messages
 - delete all messages from a certain category (i.e. Promotions, Forums, Social...)
 - delete all messages from a certain user
 - clear trash
 - clear spam
 - delete messages matching custom filter
 - Search for emails

**WARNING:** All messages will be deleted permanently (**not** moved to **Trash**).

