#!/usr/bin/env python
# coding: utf8

import ldap
import ldap.modlist as modlist
import random
import string

"""
LDAP bind user credentials. Be aware that your user must have sufficient permissions to execute the following 
functions. By default, a user can read the entire Active Directory but not create a user for example.
"""

AD_BIND_USER = "CN=bind_user,OU=ORGANIZATIONAL_UNIT,OU=DIRECTORY,DC=my_dc,DC=local"
AD_BIND_PWD = "SuperSecureAndSecretPassword"  # You should protect this information !

# Comma separated list of Active Directory Servers. You can use either ldap or ldaps adresses.
AD_SERVERS = "ldaps://active_directory01.my_dc.local:636, ldaps://active_directory02.my_dc.local:636"

# Base DN of your Active Directory
AD_BASE_DN = "OU=MY_ORGANIZATIONAL_UNIT,DC=my_dc,DC=local"

AD_DOMAIN = "@my_domain.local"


def gen_random_passwd(lenght):
    """
    Permet de générer aléatoirement un password avec majucsule, minuscule et chiffres
    :param lenght: Longueur du mot de passe à générer (int)
    :return: Mot de passe (str)
    """

    if not isinstance(lenght, int):
        raise TypeError("'Lenght' parametter should be an integer")

    passwd = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=lenght))
    return passwd


def ad_auth(username=AD_BIND_USER, password=AD_BIND_PWD, address=AD_SERVERS):
    """
    Permet d'initier une connection avec Windows Active Directory
    :param username: DN (Distinguished Name) de l'utilisateur avec lequel initier la connection
    :param password: Mot de passe de l'utilisateur AD avec lequel initier la connection
    :param address: URI des serveurs Active Directory, séparés par une virgule, de type str.
    exemple : address="ldaps://serv_ad01.domain.local:636, ldaps://serv_ad02.domain.local:636"
    :return:
    conn : Connection Active Directory si succès. Sinon, l'erreure rencontrée
    """
    conn = ldap.initialize(address)
    conn.protocol_version = 3
    conn.set_option(ldap.OPT_REFERRALS, 0)

    try:
        conn.simple_bind_s(username, password)
        print("Succesfully authenticated")
    except ldap.INVALID_CREDENTIALS:
        return "Invalid credentials"
    except ldap.SERVER_DOWN:
        return "Server down"
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            return "Other LDAP error: " + e.message['desc']
        else:
            return "Other LDAP error: " + e

    return conn


def get_users_from_ou(ad_conn, basedn=AD_BASE_DN, only_active_users=True):
    """
    Permet de retrouver tous les utilisateurs contenus dans une OU (Organizational Unit) et sous dossiers.
    :param ad_conn: connection Active Directory (un utilisateur sans droits admin suffit pour lire un AD)
    :param basedn: DN de la base à partir de laquelle on recherche les utilisateurs
    :param only_active_users: Booléen. Si 'True', seul les utilisateurs actif seront recherchés (comportement
    par défaut)
    :return: Liste des DN utilisateurs contenus dans l'OU et sous-OU.
    """

    ad_filter = "(&(objectClass=USER))"

    if only_active_users:
        ad_filter = "(&(objectClass=USER)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    results = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)

    users_dn = []

    if results:
        for user in results:
            users_dn.append(user[1]['sAMAccountName'])

    return users_dn


def get_infos_by_username(username, ad_conn, basedn=AD_BASE_DN):
    """
    Récupère les infos d'un utilisateur de part son 'sAMAccountName'
    :param username: "sAMAccountName" renseigné dans la fiche de l'utilisateur Windows Active Directory
    :param ad_conn: connection Active Directory (un utilisateur sans droits admin suffit pour lire un AD)
    :param basedn: DN (Distinguished Name) de la base à partir de laquelle on effectue la recherche sur l'AD.
    :return: DN (Distinguished Name) de l'utilisateur recherché si celui-ci est trouvé. Sinon, retourne une chaîne vide.
    """

    ad_filter = "(&(objectClass=USER)(sAMAccountName={}))".format(username)

    results = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)

    return results


def get_infos_by_dn(user_dn, ad_conn, basedn=AD_BASE_DN):
    """
    Récupère les infos d'un utilisateur de part son 'DN'
    :param user_dn: "DN" renseigné dans la fiche de l'utilisateur Windows Active Directory
    :param ad_conn: connection Active Directory (un utilisateur sans droits admin suffit pour lire un AD)
    :param basedn: DN (Distinguished Name) de la base à partir de laquelle on effectue la recherche sur l'AD.
    :return: DN (Distinguished Name) de l'utilisateur recherché si celui-ci est trouvé. Sinon, retourne une chaîne vide.
    """

    ad_filter = "(&(objectClass=USER)(distinguishedName={}))".format(user_dn)

    results = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)

    return results


def get_group_members(group_name, ad_conn, basedn=AD_BASE_DN):
    """
    Permet de récupérer la liste des utilisateurs d'un groupe sur Windows Active Directory.
    :param group_name: Nom du groupe à rechercher
    :param ad_conn: connection Active Directory (un utilisateur sans droits admin suffit pour lire un AD)
    :param basedn: DN (Distinguished Name) de la base à partir de laquelle on effectue la recherche sur l'AD.
    :return: Liste des DN des membres contenu dans le groupe demandé.
    """

    search_filer = "(&(objectClass=GROUP)(cn={0}))".format(group_name)

    result = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, search_filer)

    return result


def add_user(ad_conn, firstname, lastname, email, ou_location_dn, **kwargs):
    """
    Création d'un nouvel utilisateur (actif) sur Windows Active Directory. Ce nouvel utilisateur devra changer son
    mot de passe à la première connexion.
    :param ad_conn: connection Active Directory possédant les droits nécessaires pour créer un utilisateur
    :param firstname: Prénom de l'utilisateur à créer
    :param lastname: Nom de l'utilisateur à créer
    :param email: email de l'utilisateur à renseigner dans la fiche Active Directory créée
    :param ou_location_dn: DN (Distinguished Name) de l'OU (Organizational Unit) dans laquelle créer le nouvel
    utilisateur sur l'Active Directory
    :param kwargs: Voici la liste des kwargs disponible :
    - memberOf : Liste contenant les DN des groupes (encodés en bytes) à ajouter au nouvel utilisateur créé
    :return: Password temporaire du nouvel utilisateur créé
    """

    firstname = firstname.capitalize()
    lastname = lastname.capitalize()

    password = gen_random_passwd(15)

    username = (firstname[0] + lastname).lower()

    principal_name = username + AD_DOMAIN

    compute_name = "{} {}".format(firstname, lastname)
    # The dn of our new entry/object
    user_dn = "cn={},{}".format(compute_name, ou_location_dn)

    # A dict to help build the "body" of the object
    attrs = dict()
    attrs['objectclass'] = [b'top', b'person', b'organizationalPerson', b'user']
    attrs['mail'] = [bytes(email, 'utf-8')]
    attrs['cn'] = [bytes(compute_name, 'utf-8')]
    attrs['sAMAccountname'] = [bytes(username, 'utf-8')]
    attrs['givenName'] = [bytes(firstname, 'utf-8')]
    attrs['memberOf'] = []
    attrs['sn'] = [bytes(lastname, 'utf-8')]
    attrs['displayName'] = [bytes(compute_name, 'utf-8')]
    attrs['userPrincipalName'] = bytes(principal_name, 'utf-8')
    attrs['sAMAccountName'] = [bytes(compute_name, 'utf-8')]

    # Some flags for userAccountControl property
    # complete list here :
    # support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties

    SCRIPT = 1
    ACCOUNTDISABLE = 2
    HOMEDIR_REQUIRED = 8
    PASSWD_NOTREQD = 32
    NORMAL_ACCOUNT = 512
    DONT_EXPIRE_PASSWORD = 65536
    TRUSTED_FOR_DELEGATION = 524288
    PASSWORD_EXPIRED = 8388608

    # Impossible de créer directement un compte activé
    control_property_code = str(NORMAL_ACCOUNT + ACCOUNTDISABLE)
    attrs['userAccountControl'] = [bytes(control_property_code, 'utf-8')]

    ldif = modlist.addModlist(attrs)

    try:
        ad_conn.add_s(user_dn, ldif)
    except ldap.LDAPError as e:
        raise ValueError('Error while creating user {}. error:{}'.format(user_dn, e))

    # Change password
    newpwd_utf16 = '"{}"'.format(password).encode('utf-16-le')

    mod_list = [
        (ldap.MOD_REPLACE, "unicodePwd", newpwd_utf16),
    ]

    ad_conn.modify_s(user_dn, mod_list)

    # enable account and set User must change password at next logon
    control_property_code = str(NORMAL_ACCOUNT)

    user_account_control = [(ldap.MOD_REPLACE, "userAccountControl", [bytes(control_property_code, 'utf-8')])]
    user_must_change_pwd = [(ldap.MOD_REPLACE, "pwdLastSet", b'0')]  # Set User must change password option

    try:
        ad_conn.modify_s(user_dn, user_account_control)
        ad_conn.modify_s(user_dn, user_must_change_pwd)
    except ldap.LDAPError as e:
        print('Error while enabling or changing password of user {}. error:{}'.format(user_dn, e))

    # Add memberOf from template
    if 'memberOf' in kwargs:
        member_of = kwargs['memberOf']
        for group_dn in member_of:
            add_user_to_group_control = [(ldap.MOD_ADD, "member", [bytes(user_dn, 'utf-8')])]
            try:
                ad_conn.modify_s(group_dn.decode("utf-8"), add_user_to_group_control)
            except ldap.LDAPError as e:
                print('Error while ading the user {} to the group {}. error:{}'.format(user_dn, group_dn, e))

    return password


def copy_user_from_template(ad_conn, template_name, firstname, lastname, email):
    """
    Permet de créer un utilisateur et de lui attribuer les mêmes groupes qu'un autre utilisateur
    :param ad_conn: connection Active Directory possédant les droits nécessaires pour créer un utilisateur
    :param template_name: CN de l'utilisateur qui sert de template
    :param firstname: Prénom de l'utilisateur à créer
    :param lastname: Nom de famille de l'utilisateur à créer
    :param email: email de l'utilisateur à créer
    :return: Mot de passe temporaire de l'utilisateur créé
    """

    template_infos = get_infos_by_username(username=template_name, ad_conn=ad_conn, basedn=AD_BASE_DN)
    if template_infos:
        for dn, attr in template_infos:
            template_dn = dn
            template_attr = attr

        ou_dn = ",".join(template_dn.split(",")[1:])

        if 'memberOf' in template_attr and template_attr['memberOf']:
            template_member_of = template_attr['memberOf']

            temporary_password = add_user(ad_conn=ad_conn,
                                          firstname=firstname,
                                          lastname=lastname,
                                          email=email,
                                          ou_location_dn=ou_dn,
                                          memberOf=template_member_of)

        else:
            temporary_password = add_user(ad_conn=ad_conn,
                                          firstname=firstname,
                                          lastname=lastname,
                                          email=email,
                                          ou_location_dn=ou_dn)

        return temporary_password

    else:
        raise ValueError("'{}' doesn't on your Active Directory".format(template_name))
