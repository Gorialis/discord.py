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

    from discord.opus import Decoder, Encoder

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
        pcm_data += struct.pack('h', int(value)) * encoder.CHANNELS

    # Ensure data generated is of correct form
    assert len(pcm_data) == (encoder.FRAME_SIZE * frames_per_second)

    # Encode the data
    opus_packets = []

    for index in range(0, len(pcm_data), encoder.FRAME_SIZE):
        encoded = encoder.encode(pcm_data[index : index + encoder.FRAME_SIZE], encoder.SAMPLES_PER_FRAME)
        opus_packets.append(encoded)

    # Prepare to encrypt the data
    import nacl.secret
    import nacl.utils

    # Generate a random secret key and create an encryption box
    secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(secret_key)

    # Encrypt the data
    encrypted_packets = []

    for packet in opus_packets:
        encrypted_data = box.encrypt(packet)

        # Check message length
        assert len(encrypted_data) == len(packet) + box.NONCE_SIZE + box.MACBYTES

        encrypted_packets.append(encrypted_data)

    # Decrypt the data
    decrypted_packets = []

    for packet, original_packet in zip(encrypted_packets, opus_packets):
        decrypted_data = box.decrypt(packet)

        # Ensure data matches
        assert decrypted_data == original_packet

        decrypted_packets.append(decrypted_data)

    # Create decoder
    decoder = Decoder()
    decoder.set_volume(1.0)

    # Decode the data
    decoded_pcm = b''

    for packet in decrypted_packets:
        decoded_pcm += decoder.decode(packet)
    
    assert len(decoded_pcm) == len(pcm_data)

    # If we were dealing with completely clean data, we could compare the PCM with an error region and just call it a day.
    # Unfortunately for us, opus is smarter than this.
    # The compression introduces subtle frequencies of noise that are inaudible but show up in a spectogram,
    #  and, consequently, show up in our raw PCM data as well
    # If we implemented a Fourier transform and did frequency analysis against the Middle C,
    #  we'd be able to actually test that our PCM is good.
    # This, however, is way out of the scope of this unit test without external dependencies.
