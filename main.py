"""
Password Manager & Generator
File: password_manager.py

Features:
- Initialize an encrypted vault protected by a master password
- Add / get / list / update / delete entries (site, username, password, notes)
- Support multiple accounts per site (each entry has a unique id)
- Generate passwords interactively based on length, include numbers/specials/upper, allow repeats
- Vault is stored as a JSON object encrypted with Fernet using a key derived from the master password

Usage:
  python password_manager.py init
  python password_manager.py add --site example.com --user alice
  python password_manager.py get --site example.com [--id <entry-id>]
  python password_manager.py list
  python password_manager.py update --site example.com --id <entry-id>
  python password_manager.py delete --site example.com --id <entry-id>
  python password_manager.py generate

Make sure to `pip install cryptography` before running.
"""

import argparse
import base64
import getpass
import json
import os
import secrets
import string
import uuid
from typing import Dict, Optional, List

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VAULT_PATH = "vault.dat"
KDF_ITERATIONS = 600_000
SALT_SIZE = 16

_CURRENT_KEY: Optional[bytes] = None


def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


def init_vault(path: str = VAULT_PATH) -> None:
    global _CURRENT_KEY

    if os.path.exists(path):
        confirm = input(f"Vault '{path}' already exists. Overwrite? (y/n): ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    master = getpass.getpass("Choose a master password: ")
    master2 = getpass.getpass("Confirm master password: ")

    if master != master2:
        print("Passwords did not match. Aborting.")
        return

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(master, salt)
    f = Fernet(key)

    vault = {}
    payload = json.dumps(vault).encode("utf-8")
    token = f.encrypt(payload)

    wrapper = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "data": base64.b64encode(token).decode("utf-8"),
    }

    with open(path, "w") as fh:
        json.dump(wrapper, fh)

    _CURRENT_KEY = key

    print(f"Initialized new vault at '{path}'. Keep your master password safe.")


def load_vault(path: str = VAULT_PATH) -> Dict[str, List[Dict]]:
    global _CURRENT_KEY

    if not os.path.exists(path):
        raise FileNotFoundError("Vault file not found. Run 'init' to create one.")

    with open(path, "r") as fh:
        wrapper = json.load(fh)

    salt = base64.b64decode(wrapper["salt"].encode("utf-8"))
    token = base64.b64decode(wrapper["data"].encode("utf-8"))

    if _CURRENT_KEY is None:
        master = getpass.getpass("Enter master password: ")
        key = derive_key(master, salt)
    else:
        key = _CURRENT_KEY

    f = Fernet(key)

    try:
        plaintext = f.decrypt(token)
    except Exception:
        raise ValueError("Incorrect master password or vault corrupted.")

    _CURRENT_KEY = key

    vault = json.loads(plaintext.decode("utf-8"))

    return vault


def save_vault(vault: Dict[str, List[Dict]], path: str = VAULT_PATH) -> None:
    global _CURRENT_KEY

    if not os.path.exists(path):
        raise FileNotFoundError("Vault file not found. Run 'init' to create one.")

    with open(path, "r") as fh:
        wrapper = json.load(fh)

    salt = base64.b64decode(wrapper["salt"].encode("utf-8"))

    if _CURRENT_KEY is None:
        master = getpass.getpass(
            "Enter master password to save (will be used to re-encrypt): "
        )
        key = derive_key(master, salt)
    else:
        key = _CURRENT_KEY

    f = Fernet(key)

    payload = json.dumps(vault).encode("utf-8")
    token = f.encrypt(payload)

    wrapper["data"] = base64.b64encode(token).decode("utf-8")

    with open(path, "w") as fh:
        json.dump(wrapper, fh)

    print("Vault saved.")


def generate_password_interactive() -> str:
    while True:
        try:
            length = int(input("Password length (e.g. 16): "))

            if length <= 0:
                print("Length must be positive.")
                continue

            break

        except ValueError:
            print("Enter a valid integer.")

    include_specials = (
        input("Include special characters? (y/n): ").strip().lower() == "y"
    )

    include_numbers = (
        input("Include numbers? (y/n): ").strip().lower() == "y"
    )

    include_uppercase = (
        input("Include uppercase letters? (y/n): ").strip().lower() == "y"
    )

    allow_repeat = (
        input("Allow characters to repeat? (y/n): ").strip().lower() == "y"
    )

    characters = list(string.ascii_lowercase)

    if include_uppercase:
        characters.extend(list(string.ascii_uppercase))

    if include_numbers:
        characters.extend(list(string.digits))

    if include_specials:
        characters.extend(list(string.punctuation))

    if not characters:
        raise ValueError("No character types selected.")

    unique_count = len(characters)

    if not allow_repeat and length > unique_count:
        raise ValueError(
            f"Cannot create {length}-char password without repeats from {unique_count} unique chars."
        )

    if allow_repeat:
        return ''.join(
            secrets.choice(characters)
            for _ in range(length)
        )

    else:
        chars = characters.copy()
        out = []

        for _ in range(length):
            idx = secrets.randbelow(len(chars))
            out.append(chars.pop(idx))

        return ''.join(out)


def generate_numeric_id(entries: List[Dict]) -> str:
    used_ids = set()

    for entry in entries:
        entry_id = str(entry.get("id", ""))

        if entry_id.isdigit():
            used_ids.add(int(entry_id))

    numeric_id = 1

    while numeric_id in used_ids:
        numeric_id += 1

    return str(numeric_id)


def custom_id_exists(entries: List[Dict], custom_id: str) -> bool:
    for entry in entries:
        if str(entry.get("id", "")) == custom_id:
            return True

    return False


def add_entry(args) -> None:
    vault = load_vault()

    site = args.site

    username = (
        args.user
        if args.user is not None
        else input("Username (leave blank if none): ")
    )

    if args.password:
        password = args.password

    else:
        use_gen = (
            input("Generate password now? (y/n): ").strip().lower() == "y"
        )

        if use_gen:
            password = generate_password_interactive()
            print(f"Generated password: {password}")

        else:
            password = getpass.getpass("Enter password: ")

    notes = input("Notes (optional): ")

    if site in vault:
        if not isinstance(vault[site], list):
            vault[site] = [vault[site]]
    else:
        vault[site] = []

    entries = vault[site]

    use_custom_id = (
        input("Do you want to use a custom ID? (y/n): ").strip().lower()
    )

    if use_custom_id == "y":
        while True:
            custom_id = input("Enter custom ID: ").strip()

            if not custom_id:
                print("ID cannot be empty.")
                continue

            if custom_id_exists(entries, custom_id):
                print(
                    f"An entry with ID '{custom_id}' already exists for site '{site}'."
                )
                continue

            entry_id = custom_id
            break

    else:
        entry_id = generate_numeric_id(entries)

    entry = {
        "id": entry_id,
        "username": username,
        "password": password,
        "notes": notes,
    }

    vault[site].append(entry)

    save_vault(vault)

    print(f"Added entry for site '{site}' with id {entry['id']}")


def get_entry(args) -> None:
    vault = load_vault()

    site = args.site

    if site not in vault or not vault[site]:
        print(f"No entries found for '{site}'.")
        return

    entries = vault[site]

    if args.id:
        found = next(
            (e for e in entries if str(e.get("id")) == str(args.id)),
            None
        )

        if not found:
            print(f"No entry with id {args.id} for site '{site}'.")
            return

        print(f"Site: {site}")
        print(f"ID: {found.get('id')}")
        print(f"Username: {found.get('username', '')}")
        print(f"Password: {found.get('password', '')}")
        print(f"Notes: {found.get('notes', '')}")

        return

    if len(entries) == 1:
        e = entries[0]

        print(f"Site: {site}")
        print(f"ID: {e.get('id')}")
        print(f"Username: {e.get('username', '')}")
        print(f"Password: {e.get('password', '')}")
        print(f"Notes: {e.get('notes', '')}")

        return

    print(f"Multiple entries for '{site}':")

    for e in entries:
        print(
            f"- id: {e.get('id')}  username: {e.get('username', '')}"
        )

    print(
        "Run the same command with --id <entry-id> to view the full entry."
    )


def list_entries(args) -> None:
    vault = load_vault()

    if not vault:
        print("Vault is empty.")
        return

    print("Stored sites:")

    for site in sorted(vault.keys()):
        count = len(vault[site]) if isinstance(vault[site], list) else 1
        print(f"- {site} ({count} entries)")


def update_entry(args) -> None:
    vault = load_vault()

    site = args.site

    if site not in vault or not vault[site]:
        print(f"No entries found for '{site}'.")
        return

    entries = vault[site]

    found = next(
        (e for e in entries if str(e.get("id")) == str(args.id)),
        None
    )

    if not found:
        print(f"No entry with id {args.id} for site '{site}'.")
        return

    print(f"Updating entry for site '{site}'.")
    print(f"ID: {found.get('id')}")
    print("The ID cannot be changed.")

    current_username = found.get("username", "")
    current_password = found.get("password", "")
    current_notes = found.get("notes", "")

    print()
    print(f"Current username: {current_username}")

    new_username = input(
        "New username (press Enter to keep current): "
    )

    if new_username == "":
        new_username = current_username

    print()
    print("Password options:")
    print("1. Keep current password")
    print("2. Enter a new password")
    print("3. Generate a new password")

    while True:
        password_choice = input("Choose an option (1/2/3): ").strip()

        if password_choice == "1":
            new_password = current_password
            break

        elif password_choice == "2":
            new_password = getpass.getpass("Enter new password: ")
            break

        elif password_choice == "3":
            new_password = generate_password_interactive()
            print(f"Generated password: {new_password}")
            break

        else:
            print("Please choose 1, 2, or 3.")

    print()
    print(f"Current notes: {current_notes}")

    new_notes = input(
        "New notes (press Enter to keep current): "
    )

    if new_notes == "":
        new_notes = current_notes

    found["username"] = new_username
    found["password"] = new_password
    found["notes"] = new_notes

    save_vault(vault)

    print(
        f"Updated entry {found.get('id')} for site '{site}'."
    )


def delete_entry(args) -> None:
    vault = load_vault()

    site = args.site

    if site not in vault or not vault[site]:
        print(f"No entries for '{site}'.")
        return

    if not args.id:
        print(
            "Specify --id <entry-id> to delete a specific account for this site."
        )

        print("Entries:")

        for e in vault[site]:
            print(
                f"- id: {e.get('id')}  username: {e.get('username', '')}"
            )

        return

    new_entries = [
        e for e in vault[site]
        if str(e.get("id")) != str(args.id)
    ]

    if len(new_entries) == len(vault[site]):
        print(f"No entry with id {args.id} for site '{site}'.")
        return

    if new_entries:
        vault[site] = new_entries

    else:
        del vault[site]

    save_vault(vault)

    print(
        f"Deleted entry {args.id} from site '{site}'."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Simple encrypted password manager + generator"
    )

    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser(
        "init",
        help="Create a new vault"
    )

    p_add = sub.add_parser(
        "add",
        help="Add a site entry"
    )

    p_add.add_argument(
        "--site",
        required=True
    )

    p_add.add_argument(
        "--user",
        required=False
    )

    p_add.add_argument(
        "--password",
        required=False,
        help="Provide a password directly (not recommended)"
    )

    p_get = sub.add_parser(
        "get",
        help="Retrieve site entry or list entries"
    )

    p_get.add_argument(
        "--site",
        required=True
    )

    p_get.add_argument(
        "--id",
        required=False
    )

    sub.add_parser(
        "list",
        help="List stored sites"
    )

    p_update = sub.add_parser(
        "update",
        help="Update an existing site entry"
    )

    p_update.add_argument(
        "--site",
        required=True
    )

    p_update.add_argument(
        "--id",
        required=True
    )

    p_del = sub.add_parser(
        "delete",
        help="Delete a specific site entry"
    )

    p_del.add_argument(
        "--site",
        required=True
    )

    p_del.add_argument(
        "--id",
        required=False
    )

    sub.add_parser(
        "generate",
        help="Launch interactive password generator"
    )

    args = parser.parse_args()

    if args.cmd == "init":
        init_vault()

    elif args.cmd == "add":
        add_entry(args)

    elif args.cmd == "get":
        get_entry(args)

    elif args.cmd == "list":
        list_entries(args)

    elif args.cmd == "update":
        update_entry(args)

    elif args.cmd == "delete":
        delete_entry(args)

    elif args.cmd == "generate":
        try:
            pwd = generate_password_interactive()
            print(f"Generated password: {pwd}")

        except Exception as e:
            print("Error:", e)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
