# -*- coding: utf-8 -*-
# WARNING!!
# This is my approach to generate the authorization header.
# Ugly, might not efficient. Feel free to open a pull request.
# Reference: https://tools.ietf.org/html/draft-hammer-oauth-10
import hmac
import random
import time
from hashlib import sha1
from base64 import b64encode
from urllib.parse import quote, urlparse, urlencode, parse_qsl


SORT_PARAM = {
    "price", "date", "thread", "popular", "score", "title", "username",
    "last_post", "lastpost", "most_replies", "most_shares", "most_views"
}

ORDER_PARAM = {"asc", "desc"}


def generate_nonce(length=19):
    return ''.join(
        [str(random.SystemRandom().randint(0, 9)) for i in range(length)]
    )


def generate_param(key):
    return {
        "oauth_consumer_key": key,
        "oauth_nonce": generate_nonce(),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": int(time.time() - 30000),
        "oauth_version": "1.0"
    }


def generate_base_string(method, uri, parameters):
    parsed = urlparse(uri)
    base_string_uri = quote("{}://{}{}".format(parsed.scheme, parsed.netloc,
                                               parsed.path), "")
    uri_param = [
        urlencode([p], quote_via=quote) for p in parse_qsl(parsed.query, True)
    ]
    request_param = [
        urlencode([p], quote_via=quote) for p in parameters.items()
    ]
    normalized_param = quote('&'.join(sorted(uri_param + request_param)), "")
    return "{}&{}&{}".format(method, base_string_uri, normalized_param)


def generate_signature(base_string, consumer_secret, token_secret=''):
    hmac_key = "{}&{}".format(quote(consumer_secret), token_secret)
    signature_hash = hmac.new(hmac_key.encode(), base_string.encode(), sha1)
    return quote(b64encode(signature_hash.digest()).decode())


def generate_header(parameters):
    oauth_param = [
        '{}="{}"'.format(k, v) for k, v in sorted(parameters.items())
    ]
    return "OAuth {}".format(', '.join(oauth_param))


def prepare(uri, method, key, consumer_secret, token_secret=''):
        param = generate_param(key)
        base = generate_base_string(method, uri, param)
        sign = generate_signature(base, consumer_secret, token_secret)
        param['oauth_signature'] = sign
        return {"Authorization": generate_header(param)}


def make_query(sort=None, order=None, page=None, cursor=None, limit=None,
               expand_spoiler=None, image=None, night_mode=None,
               view_result=None, clean=None, resize_ratio=None, width=720):
    param = {}
    if sort in SORT_PARAM:
        param['sort'] = sort

    if order in ORDER_PARAM:
        param['order'] = order

    if page is not None:
        param['page'] = page

    if cursor is not None:
        param['cursor'] = cursor

    if limit is not None:
        param['limit'] = limit

    if expand_spoiler in {"true", "false"}:
        param['expand_spoiler'] = expand_spoiler

    if image in {"on", "off"}:
        param['image'] = image

    if night_mode in {"on", "off"}:
        param['night_mode'] = night_mode

    if clean is not None:
        param['clean'] = clean

    if view_result in {"true", "false"}:
        param['view_result'] = view_result

    if resize_ratio in {"r", "c"}:
        param['resize_ratio'] = resize_ratio

    param['width'] = width
    return '&'.join([f"{k}={v}" for k, v in param.items()])
