# -*- coding: utf-8 -*-

"""

test_importable.py
~~~~~~~~~~~~~~~~~~~

This test checks the functionality of functions in discord.utils

"""

import collections
import datetime
import random

import pytest


def test_snowflake_conversion():
    from discord import utils

    now = datetime.datetime.utcnow()

    snowflake = utils.time_snowflake(now)
    time = utils.snowflake_time(snowflake)

    # Accept a millisecond or less of error
    assert abs((time - now).total_seconds()) <= 0.001

def test_find():
    from discord import utils

    FakeModel = collections.namedtuple('FakeModel', 'data')

    # Generate a random collection of instances
    instances = [
        FakeModel(data=bytes([random.randrange(256) for j in range(128)]))
        for i in range(256)
    ]

    # Select a model to be found
    model_to_find = instances[0]

    # Shuffle instances
    random.shuffle(instances)

    # Ensure the model is found
    assert utils.find(lambda m: m.data == model_to_find.data, instances) == model_to_find

def test_get():
    from discord import utils

    FakeModel = collections.namedtuple('FakeModel', 'data')

    # Generate a random collection of instances
    instances = [
        FakeModel(data=bytes([random.randrange(256) for j in range(128)]))
        for i in range(256)
    ]

    # Select a model to be found
    model_to_find = instances[0]

    # Shuffle instances
    random.shuffle(instances)

    # Ensure the model is found
    assert utils.get(instances, data=model_to_find.data) == model_to_find

def test_snowflake_list():
    from discord import utils

    # Generate a list of snowflakes
    # Upper bound is the maximum size of an unsigned long long
    snowflakes = [random.randint(10000000000000000, (2 ** 64) - 1) for i in range(128)]
    # Remove duplicates
    snowflakes = set(snowflakes)

    snowflake_list = utils.SnowflakeList([])

    for snowflake in snowflakes:
        assert not snowflake_list.has(snowflake)
        assert snowflake_list.get(snowflake) is None

        snowflake_list.add(snowflake)

        assert snowflake_list.has(snowflake)
        assert snowflake_list.get(snowflake) == snowflake

@pytest.mark.parametrize(
    ('expected', 'url'),
    [
        ("abcdef", "discord.gg/abcdef"),
        ("abcdef", "http://discordapp.com/invite/abcdef"),
        ("abcdef", "http://discord.com/invite/abcdef"),
        ("abcdef", "http://discord.gg/abcdef"),
        ("abcdef", "https://discordapp.com/invite/abcdef"),
        ("abcdef", "https://discord.com/invite/abcdef"),
        ("abcdef", "https://discord.gg/abcdef"),
    ]
)
def test_resolve_invite(expected, url):
    from discord import utils

    assert utils.resolve_invite(url) == expected

@pytest.mark.parametrize(
    ('expected', 'url'),
    [
        ("abcdef", "discord.new/abcdef"),
        ("abcdef", "http://discordapp.com/template/abcdef"),
        ("abcdef", "http://discord.com/template/abcdef"),
        ("abcdef", "http://discord.new/abcdef"),
        ("abcdef", "https://discordapp.com/template/abcdef"),
        ("abcdef", "https://discord.com/template/abcdef"),
        ("abcdef", "https://discord.new/abcdef"),
    ]
)
def test_resolve_template(expected, url):
    from discord import utils

    assert utils.resolve_template(url) == expected

@pytest.mark.asyncio
async def test_maybe_coroutine():
    from discord import utils

    def function_1():
        return 1

    assert await utils.maybe_coroutine(function_1) == 1

    async def function_2():
        return 2

    assert await utils.maybe_coroutine(function_2) == 2

@pytest.mark.parametrize(
    ('original', 'escaped'),
    [
        ("**hello**", r"\*\*hello\*\*"),
        ("__hello__", r"\_\_hello\_\_"),
        ("~~hello~~", r"\~\~hello\~\~"),
    ]
)
def test_escape_markdown(original, escaped):
    from discord import utils

    assert utils.escape_markdown(original) == escaped

@pytest.mark.parametrize(
    ('original', 'escaped'),
    [
        ("@everyone", "@\u200beveryone"),
        ("@here", "@\u200bhere"),
        ("<@123456789012345678>", "<@\u200b123456789012345678>"),
    ]
)
def test_escape_mentions(original, escaped):
    from discord import utils

    assert utils.escape_mentions(original) == escaped
