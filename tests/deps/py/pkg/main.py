import os
from pkg.util import helper
from . import models
from .sub.deep import deep


def run():
    helper()
    deep()
    return models.load(os.getcwd())
