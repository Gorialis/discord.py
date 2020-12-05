# -*- coding: utf-8 -*-

"""

test_importable.py
~~~~~~~~~~~~~~~~~~~

This test imports modules and asserts the existence of certain models.

The purpose of this test is not to be a strong test of the codebase itself,
but rather to be a sanity check that ensures glaring syntax errors or use of
compatibility-breaking Python features is caught by the test suite.

"""


def test_import_discord():
    """
    Import and model test for the `discord` namespace
    """

    import discord

    assert hasattr(discord, '__version__')
    assert hasattr(discord, 'version_info')

    assert issubclass(discord.User, discord.abc.User)
    assert issubclass(discord.User, discord.abc.Messageable)

    assert issubclass(discord.Member, discord.abc.User)
    assert issubclass(discord.Member, discord.abc.Messageable)

    assert issubclass(discord.TextChannel, discord.abc.GuildChannel)
    assert issubclass(discord.TextChannel, discord.abc.Messageable)

    assert issubclass(discord.VoiceChannel, discord.abc.GuildChannel)
    assert issubclass(discord.VoiceChannel, discord.abc.Connectable)

def test_import_ext_commands():
    """
    Import and model test for the `discord.ext.commands` namespace
    """

    import discord
    from discord.ext import commands

    assert hasattr(commands.Bot, 'on_message')
    assert issubclass(commands.Bot, commands.GroupMixin)
    assert issubclass(commands.Bot, discord.Client)

    assert issubclass(commands.Command, commands.core.Command)
    
    assert issubclass(commands.Group, commands.GroupMixin)
    assert issubclass(commands.Group, commands.core.Command)

    assert issubclass(commands.CogMeta, type)

def test_import_ext_tasks():
    """
    Import and model test for the `discord.ext.tasks` namespace
    """

    from discord.ext import tasks

    assert hasattr(tasks, 'loop')

    assert hasattr(tasks.Loop, 'start')
    assert hasattr(tasks.Loop, 'stop')
    assert hasattr(tasks.Loop, 'cancel')
