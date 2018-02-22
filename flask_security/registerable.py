# -*- coding: utf-8 -*-
"""
    flask_security.registerable
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Flask-Security registerable module

    :copyright: (c) 2012 by Matt Wright.
    :license: MIT, see LICENSE for more details.
"""

from flask import current_app as app, session
from werkzeug.local import LocalProxy

from .confirmable import generate_confirmation_link
from .signals import user_registered
from .utils import do_flash, get_message, send_mail, encrypt_password, \
    config_value


def separate_names (name, alt_name=None):
    """
    Harc - April 2017
    (Insertion to support single "Name" field for registration)
    Take a single name and turn return a dict with first, middle, last keys
    :param name: A string with a name
    :param alt_name: OPTIONAL - an alternate source of names to include if we lack at least 2 names from name - for
        example, could be screen name of a twitter user
    :return: dictionary in form of {"first_name": "John", "middle_name": "Doe", "last_name": "Smith"}
        IF ONLY ONE name found in string, aka no whitespace, and no alt_name param given then
        first_name contains the source string
    """

    names = name.split(' ')

    # Pop first item in list
    first_name = names.pop(0)
    # middle_name = None
    last_name = None

    if len (names):
        # Pop last item of list
        # last_name = names.pop()

        # We got rid of middle name so now the rest of the names are last name
        last_name = ' '.join(names)

    elif alt_name:
        last_name = alt_name

    # if len (names):
    #     # Middle name(s) are the rest of the list
    #     middle_name = ' '.join(names)

    return {
        "first_name": first_name,
        # "middle_name": middle_name if middle_name else '',
        "last_name": last_name if last_name else ''
    }

# Convenient references
_security = LocalProxy(lambda: app.extensions['security'])

_datastore = LocalProxy(lambda: _security.datastore)


def register_user(**kwargs):
    confirmation_link, token = None, None
    kwargs['password'] = encrypt_password(kwargs['password'])

    # Harc modification to Flask-Security;
    # we need to parse name from form into a dict for embedded name doc or default it
    if kwargs.get('name', None):
        name_dict = separate_names(kwargs.pop('name'))
        kwargs['name'] = name_dict
    # else:
    #     kwargs['name'] = separate_names('New User')

    # Harc modification to Flask-Security;
    # Default new users as Sellers since Buyers sign up during checkout process with explicit role
    if not kwargs.get('roles', None):
        kwargs['roles'] = ['sellers']

    # Harc modification - let's make sure email is lowercase; this should have been done by Flask-Security
    # esp. for MongoDB engine where fields/queries are all case sensitive
    kwargs['email'] = kwargs['email'].lower()
    user = _datastore.create_user(**kwargs)
    _datastore.commit()

    if _security.confirmable:
        confirmation_link, token = generate_confirmation_link(user)
        do_flash(*get_message('CONFIRM_REGISTRATION', email=user.email))

    user_registered.send(app._get_current_object(),
                         user=user, confirm_token=token)

    if config_value('SEND_REGISTER_EMAIL'):
        send_mail(config_value('EMAIL_SUBJECT_REGISTER'), user.email, 'welcome',
                  user=user, confirmation_link=confirmation_link)

    return user
