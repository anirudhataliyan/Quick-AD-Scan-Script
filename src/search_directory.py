def search_directory(connection, search_base, search_filter, attributes):
    connection.search(search_base, search_filter, attributes=attributes)
    return connection.entries