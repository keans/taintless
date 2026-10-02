import os


def clean_element_of_a_literal():
    xs = ["ls", input()]
    os.system(xs[0])


def tainted_element_of_a_literal():
    xs = ["ls", input()]
    os.system(xs[1])


def element_written_later():
    xs = ["ls", "ls"]
    xs[1] = input()
    os.system(xs[0])


def unknown_index_sees_every_element():
    xs = ["ls", input()]
    i = len(xs) - 1
    os.system(xs[i])
