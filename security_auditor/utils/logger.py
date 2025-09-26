#!/usr/bin/env python3
import logging
import os

def setup_logger(name, log_level=logging.INFO, log_dir="logs"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(log_level)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(f"{log_dir}/{name}.log")
        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

