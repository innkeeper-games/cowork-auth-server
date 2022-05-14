import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

class Emailer:

    def send_reset_password(self, username, id_):
        message = Mail(
            from_email="Cowork Support <support@joincowork.com>",
            to_emails=username,
            subject="Your request to reset your Cowork password")
        message.dynamic_template_data = {
            "id": "https://joincowork.com/auth/reset-password/" + id_,
        }
        message.template_id = "d-2b071feaa4194c1f8b6bdcd959980c74"
        try:
            sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(e.message)
    

    def send_referral_email(self, username, display_name, room_id, room_title):
        message = Mail(
            from_email="Cowork <support@joincowork.com>",
            to_emails=username)
        message.dynamic_template_data = {
            "id": "https://joincowork.com/j/" + room_id,
            "referrer_name": display_name,
            "room_title": room_title
        }
        message.template_id = "d-bebb70e12b924df99ab9e343be45d3c1"
        try:
            sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(e.message)
    

    def send_achievement_email(self, username, title, description, progress, reward):
        message = Mail(
            from_email="Cowork <support@joincowork.com>",
            to_emails=username)
        message.dynamic_template_data = {
            "title": title,
            "description": description,
            "progress": progress,
            "reward": reward
        }
        message.template_id = "d-d1e2cf3593694f8284a3c28df608f1c5"
        try:
            sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
            response = sg.send(message)
            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(e.message)


    def add_to_marketing_list(self, username, display_name):
        try:
            sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
            data = {
                "list_ids": [
                    "b7db1c70-098b-4a8a-9576-3b967fd89e65"
                ],
                "contacts": [
                    {
                        "email": username                    }
                ]
            }

            response = sg.client.marketing.contacts.put(
                request_body=data
            )

            print(response.status_code)
            print(response.body)
            print(response.headers)
        except Exception as e:
            print(e.message)