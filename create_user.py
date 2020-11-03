#!/usr/bin/python3

"""
Скрипт создания нового пользователя

"""
import sys
import re
import pwd
import secrets
import string
import os
from passlib.hash import sha512_crypt
from functools import partial
from datetime import datetime
from tld import parse_tld


def usage():
    print(f"Usage: {sys.argv[0]} <имя сайта>")
    sys.exit()


def get_user_name(site_name):
    site_name = '.'.join(  # Убираем TLD
        parse_tld(site_name, fix_protocol=True)[:-3:-1]
    )
    user_name = site_name.strip(".").replace('.', '_')

    def does_exist(user):
        try:
            pwd.getpwnam(user)
            return True
        except KeyError:  # Пользователь не найден
            return False

    def trunc_user_name(user_name, postfix):
        return f"{user_name[:8-len(str(postfix))]}{postfix}"

    postfix = ""
    while(does_exist(trunc_user_name(user_name, postfix))):
        postfix = (postfix or 0) + 1
    user_name = trunc_user_name(user_name, postfix)
    user_name = re.sub(r"[^a-z0-9_-]+", "", user_name)
    return user_name.rstrip('-')


def generate_password(length=15):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for i in range(length))


def get_sha512_hash(password):
    return sha512_crypt.using(rounds=5000).hash(password)


def add_mysrc_entry(site, user, password):
    date = datetime.now().replace(microsecond=0).isoformat()
    with open("/root/mysrc", 'a', opener=partial(os.open, mode=0o600)) as file:
        file.write(f"{date} {site} {user} {password}\n")


def main():
    if len(sys.argv) < 2:
        usage()

    site_name = sys.argv[1]
    site_name = re.sub(r"^www\.", "", site_name).lower()
    print(f"Создание сайта {site_name}...")

    user_name = get_user_name(site_name)
    password = generate_password()
    password_hash = get_sha512_hash(password)
    status = os.WEXITSTATUS(os.system(
        f"""ansible-playbook -e "username={user_name}" \
                             -e "sitename={site_name}" \
                             -e "password_hash={password_hash}" \
                             create_user_playbook.yml""".replace('$', '\$')))
    if status == 0:
        add_mysrc_entry(site_name, user_name, password)
    else:
        print(
            f"При выполнении ansible-playbook произошла ошибка. Код возврата: {status}", file=sys.stderr)


if __name__ == "__main__":
    main()
