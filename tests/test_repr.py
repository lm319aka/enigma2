import pytest
import numpy as np
from enigma2 import (
    E2, _E2, E2Async, _E2Async,
    E2Config, _E2Config,
    E2Generator,
    E2Params, _E2Params
)
from enigma2.config.model_params import _E2ElementsCreationParams

def test_repr_params():
    params = E2Params(pwd=b"secretpassword")
    repr_str = repr(params)
    assert "E2Params(" in repr_str
    assert "pwd=b'secretpassword'" in repr_str
    assert "encoding=E2Encoding(encoding='utf-8'" in repr_str
    assert "\n" in repr_str
    
    creation_params = _E2ElementsCreationParams(rotations_seed=42)
    repr_creation = repr(creation_params)
    assert "_E2ElementsCreationParams(" in repr_creation
    assert "rotations_seed=42" in repr_creation
    assert "\n" in repr_creation

def test_repr_config():
    params = E2Params(pwd=b"secretpassword")
    config = E2Config(params)
    repr_str = repr(config)
    assert "E2Config(" in repr_str
    assert "pwd=b'secretpassword'" in repr_str
    assert "dtype=" in repr_str
    assert "btype=256" in repr_str
    assert "rotations_seed=" in repr_str
    assert "\n" in repr_str

def test_repr_generator():
    params = E2Params(pwd=b"secretpassword")
    config = E2Config(params)
    generator = E2Generator(config)
    repr_str = repr(generator)
    assert "E2Generator(" in repr_str
    assert "config=E2Config(" in repr_str
    assert "\n" in repr_str

def test_repr_cipher():
    params = E2Params(pwd=b"secretpassword")
    cipher = E2(params)
    repr_str = repr(cipher)
    assert "E2(" in repr_str
    assert "config=E2Config(" in repr_str
    assert "\n" in repr_str

    async_cipher = E2Async(params)
    repr_async = repr(async_cipher)
    assert "E2Async(" in repr_async
    assert "config=E2Config(" in repr_async
    assert "\n" in repr_async
