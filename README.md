# SNIPy

Parses a TLS ClientHello message and gets servername via ServerName Indication(SNI).

Works with Python 3.

To test run 
```
test_server.py 0.0.0.0 8000
```
which listens for tls/https connections and outputs the servername 
and then kills the connection.
