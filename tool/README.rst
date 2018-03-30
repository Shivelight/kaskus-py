Tool to extract ``consumer key`` from Kaskus native app using LSB2bit algorithm and some decryption.

How to use
----------

1. Install Pillow

::

    $ pip install Pillow

2. Extract ``splash.png`` from the APK file and put it in the tool directory.

3. Extract the pixels to decrypt.

::

    $ python extract_pixels.py

4. Finally decrypt the pixels.

::

    $ java -jar decrypt.jar
