# GrabME
Sensitive information extraction tool.

Platform:
---------
- Linux cli

Report a bug:
-------------
https://github.com/GuerrillaWarfare/GrabME/issues

Usage examples:
-------------------------
https://github.com/GuerrillaWarfare/GrabME/wiki/GrabME-Usage-Examples

    Usage: ./grabme -f [FILE] [EXTRACT-OPTION]

    Extract Options: --btc, --iat, --ipv4, --ipv6, --link
                     --mac, --ssn, --ccn, --phn, --hash

    ./grabme -a [FILE] | Grab all extract types if any in file.

    ./grabme -f [FILE] --btc | Grab bitcoin addresses if in file.

    ./grabme -f [FILE] --hash | Grab hash values if any are in file.

    ./grabme -f [FILE] --mac | Grab MAC addresses if any are in file.

    ./grabme -f [FILE] --phn | Grab Phone numbers if any are in file.

    ./grabme -f [FILE] --email | Grab Email addresses if any are in file.

    ./grabme -f [FILE] --iat | Grab instagram access tokens if any are in file.

    ./grabme -f [FILE] --ssn | Grab social security numbers if any are in file.

    ./grabme -f [FILE] --ccn | Grab credit card numbers if any are in file.

    ./grabme -f [FILE] --ipv6 | Grab IPv6 addresses if any are in file.

    ./grabme -f [FILE] --ipv4 | Grab IPv4 addresses if any are in file.

    What can it extract ?:

    1. Links
    2. Hash values
    3. Email addresses
    4. ipv4, ipv6 addresses
    5. Instagram access tokens
    6. Bitcoin wallet addresses
    7. MAC addresses with : or - (deliminators)
    8. USA Based Telephone, Social Security and Major Credit Card numbers.

Changelog:
----------
- Added extra options for specific content extraction.

Protip:
-------
- The '-a' option MAY or MAY NOT always be the best usage case.

Guerrilla Warfare Free License ("GWFL"):
----------------------------------------
- You're free to modify this software to YOUR liking or leave it as is.
- This software comes as is, and may or may not receive any additional updates.
- The initial download and use of this software constitutes that you adhere and comply to the writing of this EULA.
- The Developer is NOT at ALL under any circumstances responsible for YOUR actions or the actions of any other third party instances that may use this software for any illegal or nefarious activities.
