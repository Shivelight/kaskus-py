🍕 kaskus-py
============

.. image:: https://img.shields.io/pypi/v/kaskuspy.svg
   :target: https://pypi.python.org/pypi/kaskuspy
   :alt: PyPI - Version

.. image:: https://img.shields.io/pypi/status/kaskuspy.svg
   :target: https://pypi.python.org/pypi/kaskuspy
   :alt: PyPI - Status

.. image:: https://img.shields.io/pypi/pyversions/kaskuspy.svg
   :target: https://pypi.python.org/pypi/kaskuspy
   :alt: PyPI - Python Version

.. image:: https://img.shields.io/pypi/l/kaskuspy.svg
   :target: https://pypi.python.org/pypi/kaskuspy
   :alt: PyPI - License

*I make this wrapper to improve my python and reverse engineering skills, and to learn more about how to work with git and python packaging.*

>>> from kaskuspy import Kaskus
>>> kaskus = Kaskus()
>>> kaskus.getHotThreads()
MultipleHotThreadResponse(...)

Installation
------------

Download or clone this repository and run:

::

    python setup.py install

or via pip:

::

    pip install kaskuspy

Features
--------

- Kaskus without scraping
- Fetch the latest hot threads
- Search for threads
- *and more..*


Contributing
------------

If you would like to contribute, please check for open issues or open a new issue if you have an idea or a bug.
Follow the code style of the project and PEP8.


License
-------

The code in this project is licensed under MIT license.