# -*- coding: utf-8 -*-

"""

test_voice_dependencies.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This test checks for the availability of opus and PyNaCl and does a test encode flow.

"""

import math
import struct


def test_has_opus():
    """
    This tests that opus is loaded.
    """

    import discord

    # Create an encoder to trigger the automatic opus detection
    encoder = discord.opus.Encoder()

    assert discord.opus.is_loaded()

def test_has_nacl():
    """
    This tests that PyNaCl is loaded.
    """

    import discord

    assert discord.voice_client.has_nacl

def test_encoding():
    """
    This generates some PCM, encodes it with opus, encrypts it, and then decrypts it.

    This serves as a test that the interface to opus and nacl work properly.
    """

    from discord.opus import Encoder

    encoder = Encoder()

    # We need to generate some PCM for testing
    pcm_data = b''

    # Time that passes per PCM frame
    time_per_frame = encoder.FRAME_LENGTH / 1000
    # Frames per second
    frames_per_second = int(1 / time_per_frame)
    # Time that passes per PCM sample
    time_per_sample = time_per_frame / encoder.SAMPLES_PER_FRAME
    # Maximum magnitude within PCM data type
    magnitude = (2 ** 15) - 1
    # Generate a 'Middle C' tone
    frequency = 261.625

    # Generate 1 second of PCM data
    for sample in range(encoder.SAMPLES_PER_FRAME * frames_per_second):
        sample_time = sample * time_per_sample

        value = magnitude * math.sin(2 * math.pi * sample_time * frequency)

        # Duplicate PCM value per channel
        pcm_data += struct.pack('>h', int(value)) * encoder.CHANNELS

    # Ensure data generated is of correct form
    assert len(pcm_data) == (encoder.FRAME_SIZE * frames_per_second)

    # Encode the data
    opus_data = encoder.encode(pcm_data, encoder.SAMPLES_PER_FRAME)

    # Prepare to encrypt the data
    import nacl.secret
    import nacl.utils

    # Generate a random secret key and create an encryption box
    secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(secret_key)

    # Encrypt the data
    encrypted_data = box.encrypt(opus_data)

    # Check message length
    assert len(encrypted_data) == len(opus_data) + box.NONCE_SIZE + box.MACBYTES

    # Decrypt the data
    decrypted_data = box.decrypt(encrypted_data)

    # Ensure data matches
    assert decrypted_data == opus_data
