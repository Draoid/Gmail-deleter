
from __future__ import print_function

import argparse
import sys

from gmail_handler import GmailBulkHandler
from oauth2client import tools


INVALID_INPUT_TEXT = 'Invalid input! Try again'
MENU_TEXT = """
1. Delete all messages
2. Delete messages from category
3. Delete messages from specific user
4. Empty trash
5. Empty spam
6. Delete messages from filter (format: <filter: value>)
7. Exit

WARNING: All messages will be deleted permanently (not moved to Trash).
"""

try:
    arguments = argparse.ArgumentParser(parents=[tools.argparser], description='Mass mail deleter for Gmail')
    arguments.add_argument('-s', '--secret', type=str, help='Path to the Google client secret json', required=False)
    print (arguments)
except ImportError:
    arguments = None


def main():
    args = arguments.parse_args()
    secret_file_path = args.secret

    gmail = GmailBulkHandler(secret_file_path, args)

    while True:
        print(MENU_TEXT)
        try:
            choice = int(input('Choose an option: '))
            if choice == 1:
                messages = gmail.list_messages_matching_query(query='label:all')
                gmail.delete_messages_perm(msgs=messages)
            elif choice == 2:
                labels = gmail.get_labels()
                for i, label in enumerate(labels):
                    print(str(i+1) + ': ' + label['name'])
                try:
                    label_choice = int(input('Choose label for deletion: '))
                    if label_choice <= 0 or label_choice >= len(labels) + 1:
                        print(INVALID_INPUT_TEXT)
                        continue
                except ValueError:
                    print(INVALID_INPUT_TEXT)
                else:
                    messages = gmail.list_messages_with_label(label_ids=labels[label_choice-1]['id'])
                    gmail.delete_messages_perm(msgs=messages)
            elif choice == 3:
                user_choice = str(input('Choose user whose messages you want to delete: '))
                messages = gmail.list_messages_matching_query(query=f"from: {user_choice}")
                gmail.delete_messages_perm(msgs=messages)
            elif choice == 4:
                messages = gmail.list_messages_with_label(label_ids='TRASH')
                gmail.delete_messages_perm(msgs=messages)
            elif choice == 5:
                messages = gmail.list_messages_with_label(label_ids='SPAM')
                gmail.delete_messages_perm(msgs=messages)
            elif choice == 6:
                filter_choice = str(input('Choose filter for messages you want to delete: '))
                messages = gmail.list_messages_matching_query(query=filter_choice)
                gmail.delete_messages_perm(msgs=messages)
            else:
                sys.exit(1)
        except ValueError:
            print(INVALID_INPUT_TEXT)


if __name__ == '__main__':
    main()
