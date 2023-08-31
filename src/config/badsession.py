import django.contrib.sessions.backends.db as db
from random import choice


class SessionStore(db.SessionStore):
    session_counter = 1000

    def _get_new_session_key(self):
        abc_list = ["a", "b", "c"]
        while True:
            session_key = "sid-" + str(SessionStore.session_counter) + choice(abc_list)
            SessionStore.session_counter += 5
            if not self.exists(session_key):
                return session_key
