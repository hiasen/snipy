import struct


def get_sni(data):
    """
    Parses a bytestring containing a TLS ClientHello message and returns the Server Name.

    Parsed according to:
    https://tools.ietf.org/html/rfc5246 and
    https://tools.ietf.org/html/rfc6066

    Raises AssertionError if the bytestring don't conform to the above rfc's
    Raises ValueError if no Server Name extension is found

    :param data: bytestring of first TLS segment sent from a client to a server
    :return: bytestring containing the server name
    """

    # First we parse the TLS Record Protocol
    content_type, tls_major, tls_minor, record_length = struct.unpack('>BBBH', data[:5])

    assert content_type == 22, 'Record should be of type handshake (22)'

    # Parsing TLS Hanshaking Protocol
    handshake_data = data[5:]
    assert len(handshake_data) == record_length, "Length of handshake record should be the remaining"

    handshake_type, = struct.unpack('>B', handshake_data[:1])
    assert handshake_type == 1, 'Handshaking message type should be ClientHello'
    handshake_length, = struct.unpack('>I', b'\x00' + handshake_data[1:4])

    client_hello_data = handshake_data[4:]
    assert len(client_hello_data) == handshake_length

    # Parsing Client Hello message
    # Skipping irrelevant information of static length 34 in the ClientHello message
    n = 34

    # Parsing length of more irrelevant data
    session_id_len, = struct.unpack('>B', client_hello_data[n:n+1])
    n += 1 + session_id_len
    cipher_suites_len, = struct.unpack('>H', client_hello_data[n:n+2])
    n += 2 + cipher_suites_len
    compression_methods_len, = struct.unpack('>B', client_hello_data[n:n+1])
    n += 1 + compression_methods_len

    # Finally getting to the extensions
    extensions_len, = struct.unpack('>H', client_hello_data[n:n+2])
    n += 2
    assert handshake_length == n + extensions_len

    # Searching for server name in the list of TLS-extensions the client supplies
    while n < handshake_length:
        extension_type, data_len = struct.unpack('>HH', client_hello_data[n:n+4])
        n += 4

        if extension_type == 0:
            # server_name_list_len, = struct.unpack('>H', client_hello_data[n:n+2])

            name_type = client_hello_data[n+2]
            # name type could in principle be something other than a hostname
            # but the standard has currently only hostname as a choice
            # https://tools.ietf.org/html/rfc6066#section-3
            assert name_type == 0, "name type should be a hostname."

            host_name_len, = struct.unpack('>H', client_hello_data[n+3:n+5])
            assert data_len == host_name_len + 5
            return client_hello_data[n+5:n+5+host_name_len]
        n += data_len
    raise ValueError("No Server Name Indication could be found")
