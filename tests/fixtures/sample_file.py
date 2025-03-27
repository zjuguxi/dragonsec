def insecure_function():
    password = "hardcoded_password"
    return password


def sql_query(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
