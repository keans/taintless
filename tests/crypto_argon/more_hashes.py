import metrohash
import t1ha
import spooky


def run(data):
    metrohash.hash64(data)
    t1ha.t1ha2(data)
    spooky.hash128(data)
