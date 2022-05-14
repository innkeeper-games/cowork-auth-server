import psycopg2
from database import config
from secrets import token_urlsafe
from database_connector import DatabaseConnector

class SettingsDatabaseConnector(DatabaseConnector):

    def __init__(self):
        super().__init__()
        self.connection = self.connect()


    def get_room_title(self, room_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT title FROM room WHERE id = %s""", (room_id,))
        title = cursor.fetchone()[0]
        cursor.close()
        return title


    def get_room_description(self, room_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT description FROM room WHERE id = %s""", (room_id,))
        description = cursor.fetchone()[0]
        cursor.close()
        return description


    def get_room_members(self, room_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT account_id FROM membership WHERE room_id = %s""", (room_id,))
        members = cursor.fetchall()
        cursor.close()
        return members

    def room_exists(self, room_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT public FROM room WHERE id = %(id)s""", {'id': room_id})
        exists = cursor.fetchone() is not None
        cursor.close()
        return exists
    

    def get_room_privacy(self, room_id):
        cursor = self.connection.cursor()
        cursor.execute("""SELECT public FROM room WHERE id = %(id)s""", {'id': room_id})
        public = cursor.fetchone()[0]
        cursor.close()
        return not public