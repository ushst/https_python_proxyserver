#!/usr/bin/env python3
import os
import sys
import bcrypt
import getpass

PASS_FILE = os.environ.get("PASS_FILE", "./pass")


def load_users():
    users = {}
    if os.path.exists(PASS_FILE):
        with open(PASS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                user, hash_ = line.split(":", 1)
                users[user.strip()] = hash_.strip()
    return users


def save_users(users):
    os.makedirs(os.path.dirname(PASS_FILE), exist_ok=True)
    with open(PASS_FILE, "w", encoding="utf-8") as f:
        for user, hash_ in users.items():
            f.write(f"{user}:{hash_}\n")


def add_user(username, password=None):
    users = load_users()
    if username in users:
        print(f"User '{username}' already exists")
        return
    if not password:
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match")
            return
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed
    save_users(users)
    print(f"User '{username}' added")


def delete_user(username):
    users = load_users()
    if username not in users:
        print(f"User '{username}' not found")
        return
    users.pop(username)
    save_users(users)
    print(f"User '{username}' deleted")


def list_users():
    users = load_users()
    if not users:
        print("No users")
        return
    for u in users:
        print(u)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./manage_users.py [add <user> | del <user> | list]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "add" and len(sys.argv) == 3:
        add_user(sys.argv[2])
    elif cmd == "del" and len(sys.argv) == 3:
        delete_user(sys.argv[2])
    elif cmd == "list":
        list_users()
    else:
        print("Invalid command or arguments")
        sys.exit(1)
