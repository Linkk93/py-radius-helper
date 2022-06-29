#!/usr/bin/env python3
import hmac
import hashlib


class MessageAuthenticatorNotFoundError(Exception):
    pass


def calc_message_authenticator(radius_byte_file, shared_secret: str = 'aruba123'):
    """
    Takes a RADIUS message and calculates the Message-Authenticator hash value.
    :param shared_secret: RADIUS shared secret as string
    :param radius_byte_file: byte file of the RADIUS message (Export from PCAP as bytes)
    :return: Message-Authenticator HMAC
    """
    print(f'Removing current Message-Authenticator from RADIUS packet...')
    # The Message-Authenticator field starts with the byte 5012 and is followed by 16 octets
    # During hash calculation the message-authenticator field must be 16 octets of zeros
    try:
        ma_start = radius_byte_file.find('5012')
        if ma_start == -1:
            # 5012 is not found in byte array
            raise MessageAuthenticatorNotFoundError

        ma_in_packet = radius_byte_file[ma_start + 4: ma_start + 36]
        print(f'\nThe following Message-Authenticator was found:\n{ma_in_packet}\n')
        clean_packet_hex = radius_byte_file[:ma_start + 4] + 32 * '0' + radius_byte_file[ma_start + 36:]
        clean_packet_byte = bytearray.fromhex(clean_packet_hex)
        ma_hash = hmac.new(shared_secret.encode(), clean_packet_byte, hashlib.md5).hexdigest()
        print(f'Calculated hash:\n{ma_hash}\n')

        if ma_in_packet == ma_hash:
            print('Hash in packet and calculation match!')
        else:
            print(f'!!! HASH IN PACKET AND CALCULATION DO NOT MATCH')
            print(f'!!! Check the following: ')
            print(f'!!! 1. make sure to only export the RADIUS part of the packet, no other parts, like UDP')
            print(f'!!! 2. check the shared secret')
        return ma_hash
    except Exception as e:
        print('Error working with the packet:\n')
        print(e)


if __name__ == '__main__':
    print('#' * 64)
    print(f'### Export the RADIUS message from your packet capture.')
    print(f'### Open the PCAP in Wireshark and filter "radius.code == 1"')
    print(f'### Then rightclick only the RADIUS part of the packet and choose export as bytes.')
    print('#' * 64)
    print('\n\n')

    path_radius_bytes = input('Path to byte export file:\n')
    secret = input('\nShared Secret:\n')
    print('\n')

    print(f'Trying to read: {path_radius_bytes}...\n')
    try:
        with open(path_radius_bytes, 'rb') as byte_file:
            message_body = byte_file.read().hex()
    except Exception as e:
        print('Please input the correct path to the binary file.')
        print('Script is stopping with following error:')
        print(e)
    print(f'Reading file finished.\n')
    calc_message_authenticator(message_body, secret)
    print('\n')
