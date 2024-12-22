import ldap3

def connect_to_ad(server_address, username, password):
    server = ldap3.Server(server_address, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=username, password=password, auto_bind=True)
    return conn