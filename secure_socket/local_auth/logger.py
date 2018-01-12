import inspect
import logging

logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('auth.log')
formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

file = inspect.currentframe()
