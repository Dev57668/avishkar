from sqlalchemy import text


def by_id(session, i):
    return session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": i}).fetchall()


def by_name(User, name):
    return User.objects.filter(name=name)
