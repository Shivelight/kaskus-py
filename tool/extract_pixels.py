from PIL import Image


def getIntFromColor(red, green, blue):
    """https://stackoverflow.com/a/18037185"""
    red = (red << 16) & 0x00FF0000
    green = (green << 8) & 0x0000FF00
    blue = blue & 0x000000FF
    return 0xFF000000 | red | green | blue


def toSigned32(n):
    """https://stackoverflow.com/a/37095855"""
    n = n & 0xffffffff
    return (n ^ 0x80000000) - 0x80000000


image = Image.open("splash.png")
pixels = list(image.getdata())

signed_int = [toSigned32(getIntFromColor(*x)) for x in pixels]

with open('pixels.txt', 'w+') as f:
    f.write('\n'.join(map(str, signed_int)))
