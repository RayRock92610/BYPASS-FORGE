🔒 Fix Weak SSL/TLS Verification

🎯 **What:** The vulnerability fixed
The `ssl_ctx` was configured with `check_hostname = False` and `verify_mode = ssl.CERT_NONE`. This completely disabled TLS certificate verification when the `bypass_forge_server.py` attempted to initiate requests, opening the door for Man-in-the-Middle (MitM) attacks.

⚠️ **Risk:** The potential impact if left unfixed
Without SSL verification, any attacker on the network path could intercept and read or modify traffic meant for the target URL. The server would unwittingly accept invalid or malicious certificates.

🛡️ **Solution:** How the fix addresses the vulnerability
Replaced `ssl_ctx.check_hostname = False` with `ssl_ctx.check_hostname = True` and `ssl_ctx.verify_mode = ssl.CERT_NONE` with `ssl_ctx.verify_mode = ssl.CERT_REQUIRED`. This ensures strict SSL/TLS validation and requires a valid certificate that matches the hostname to establish a secure connection.
