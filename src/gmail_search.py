from __future__ import print_function
import os.path
import webbrowser
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Если вы изменяете SCOPES, удалите файл token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Аутентификация в Gmail API."""
    creds = None
    # Файл token.json сохраняет токен доступа и обновления.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # Если нет действительных учетных данных, запросите у пользователя вход.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'client.json', SCOPES)  # Используем client.json
            creds = flow.run_local_server(port=0)
        # Сохраните учетные данные для следующего запуска.
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def search_messages(service, query):
    """Поиск писем по запросу."""
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        return messages
    except HttpError as error:
        print(f'An error occurred: {error}')
        return []

def get_message_details(service, message_id):
    """Получение деталей письма по его ID."""
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        return message
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def print_message_summary(message, index):
    """Вывод краткой информации о письме."""
    headers = message['payload']['headers']
    subject = next(header['value'] for header in headers if header['name'] == 'Subject')
    sender = next(header['value'] for header in headers if header['name'] == 'From')
    date = next(header['value'] for header in headers if header['name'] == 'Date')

    print(f"{index + 1}. Subject: {subject}")
    print(f"   From: {sender}")
    print(f"   Date: {date}")
    print("-" * 50)

def extract_message_text(message):
    """Извлечение текста письма."""
    if 'parts' in message['payload']:
        for part in message['payload']['parts']:
            if part['mimeType'] == 'text/plain':
                return part['body']['data']
            elif part['mimeType'] == 'text/html':
                return part['body']['data']
    else:
        return message['payload']['body']['data']
    return None

def print_message_text(message):
    """Вывод только текста письма."""
    body = extract_message_text(message)
    if body:
        import base64
        decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
        print(decoded_body)
    else:
        print("Текст письма недоступен.")

def open_message_in_browser(message_id):
    """Открытие письма в браузере."""
    url = f"https://mail.google.com/mail/u/0/#inbox/{message_id}"
    webbrowser.open(url)

def main():
    # Аутентификация
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    while True:
        # Пример поиска писем
        query = input("Введите запрос для поиска (например, 'from:user@example.com' или 'subject:Hello'): ")
        messages = search_messages(service, query)

        if not messages:
            print("Письма не найдены.")
        else:
            print(f"Найдено писем: {len(messages)}")
            for i, msg in enumerate(messages):
                message_details = get_message_details(service, msg['id'])
                if message_details:
                    print_message_summary(message_details, i)

            # Выбор письма для просмотра
            while True:
                try:
                    choice = input("Введите номер письма для просмотра текста (или 'q' для выхода): ").strip().lower()
                    if choice == 'q':
                        return  # Завершение программы
                    choice = int(choice) - 1
                    if 0 <= choice < len(messages):
                        selected_message = get_message_details(service, messages[choice]['id'])
                        if selected_message:
                            print("\nТекст письма:")
                            print_message_text(selected_message)

                            # Действия после вывода текста
                            while True:
                                action = input(
                                    "Выберите действие:\n"
                                    "1. Завершить программу\n"
                                    "2. Новый поиск\n"
                                    "3. Открыть письмо в браузере\n"
                                    "Ваш выбор: "
                                ).strip()
                                if action == '1':
                                    return  # Завершение программы
                                elif action == '2':
                                    break  # Новый поиск
                                elif action == '3':
                                    open_message_in_browser(messages[choice]['id'])
                                    print("Письмо открыто в браузере.")
                                else:
                                    print("Неверный выбор. Попробуйте снова.")
                        else:
                            print("Неверный номер письма. Попробуйте снова.")
                    else:
                        print("Неверный номер письма. Попробуйте снова.")
                except ValueError:
                    print("Неверный ввод. Введите номер письма или 'q' для выхода.")

if __name__ == '__main__':
    main()