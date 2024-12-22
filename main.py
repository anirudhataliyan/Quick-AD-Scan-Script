from src import connect_to_ad
from src import search_directory
from src import save_results

def main():
    print("Welcome to Active Directory Enumerator\n")
    server_address = input("Enter the Active Directory server address (e.g., ldap://domain.com): ")
    username = input("Enter the username (e.g., DOMAIN\\\\User): ")
    password = input("Enter the password: ")
    try:
        print("\nConnecting to the Active Directory...")
        conn = connect_to_ad(server_address, username, password)
        print("Connection successful!\n")
    except Exception as e:
        print(f"Failed to connect: {e}")
        return
    search_base = input("Enter the search base (e.g., DC=domain,DC=com): ")
    print("\nEnumerating objects in the directory...")

    try:
        print("Fetching user accounts...")
        users = search_directory(conn, search_base, '(objectClass=user)', ['cn', 'mail', 'memberOf'])
        user_data = [entry.entry_to_json() for entry in users]

        print("Fetching groups...")
        groups = search_directory(conn, search_base, '(objectClass=group)', ['cn', 'member'])
        group_data = [entry.entry_to_json() for entry in groups]

        print("Fetching computers...")
        computers = search_directory(conn, search_base, '(objectClass=computer)', ['cn'])
        computer_data = [entry.entry_to_json() for entry in computers]

        print("\nEnumeration completed successfully.")

        results = {
            'users': user_data,
            'groups': group_data,
            'computers': computer_data
        }

        print("\nChoose an output format:")
        print("1. JSON")
        print("2. CSV")
        output_choice = input("Enter your choice (1 or 2): ")

        if output_choice == '1':
            filename = input("Enter the JSON filename (e.g., output.json): ")
            save_to_json(results, filename)
            print(f"Results saved to {filename}.")
        elif output_choice == '2':
            filename_prefix = input("Enter the CSV filename prefix (e.g., output): ")
            save_to_csv(user_data, f"{filename_prefix}_users.csv")
            save_to_csv(group_data, f"{filename_prefix}_groups.csv")
            save_to_csv(computer_data, f"{filename_prefix}_computers.csv")
            print(f"Results saved as {filename_prefix}_users.csv, {filename_prefix}_groups.csv, and {filename_prefix}_computers.csv.")
        else:
            print("Invalid choice. No output saved.")

    except Exception as e:
        print(f"An error occurred during enumeration: {e}")
if __name__ == "__main__":
    main()
